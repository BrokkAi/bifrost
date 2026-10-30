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

#[cfg(test)]
use brokk_bifrost_test_macros::hardwon;

#[doc(hidden)]
pub mod package;

use super::precedence::{EFFECTIVE_NAMESPACES, ScopeChoice};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
    ResolutionBinaryOwnerRoute, ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
    ResolutionCallableReceiverOrigin, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteFact,
    ResolutionImportRouteKind, ResolutionImportRouteSegmentFact, ResolutionMemberKind,
    ResolutionNameId, ResolutionNamespace, ResolutionRootExportFact, ResolutionRootImportAnchor,
    ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget, ResolutionRootImportFact,
    ResolutionRootImportKind, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionRouteGap, ResolutionRouteOwner,
    ResolutionScopeFact, ResolutionScopeId, ResolutionScopeInheritance, ResolutionScopeKind,
    ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionTypeSlotId,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BoundaryStatus, HoistingClass, ResolutionCompletionReasonKind, ResolutionGapOriginKind,
};

use crate::analyzer::structural::PrecedenceTier;
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;

use super::batch::FactReferenceSiteMetadata;
use super::engine::PreloadedFragment;
use super::fact_source::{
    language_callables_occupy_value_namespace, language_explicit_imports_outrank_package_binders,
    language_implicit_root_member_names, language_lexical_binder_origin,
};
use super::local_identity::{
    ResolutionIdentityCatalogBuilder, ResolutionLookupSemanticRecipe, ResolutionNodeIdentity,
    ResolutionPathIdentity, ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
};
use super::model::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, BindingOrigin, EndpointSignature,
    PartialPath, PartialPathId, PrecedenceStep, ResolutionCompletion, ResolutionIncompleteReason,
    SemanticId, StackPattern, StackVariableId, WitnessStep, binding_origin_rank,
};
use super::{
    binder_namespace_is_declared, closed_endpoint, declaration_namespace_is_declared,
    producer_declares_definition_namespace, required_resolution_name, required_resolution_scope,
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
                ResolutionGapKind::UnsupportedExpressionType => {
                    ResolutionGapOriginKind::UnsupportedExpressionType
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
            ResolutionGapOriginKind::UnsupportedExpressionType => {
                Self::Extracted(ResolutionGapKind::UnsupportedExpressionType)
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

    /// The producer's receiver identity, including value member references.
    pub const fn receiver_origin(&self) -> Option<ResolutionCallableReceiverOrigin> {
        match self.site_metadata {
            Some(metadata) => metadata.receiver_origin(),
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
    #[doc(hidden)]
    pub paths: Vec<(PartialPathId, PartialPath)>,
    semantics: Vec<LoweredSemanticSite>,
    gaps: Vec<LoweredCoverageGap>,
    #[cfg(any(test, feature = "test-support"))]
    hierarchy_terminals: Vec<(SemanticId, BindingNodeId)>,
}

impl LoweredResolutionFragment {
    #[doc(hidden)]
    pub fn selected_include_glob(
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

    #[doc(hidden)]
    pub fn selected_include_binding(
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

    #[doc(hidden)]
    pub fn selected_include_continuation(
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

    #[doc(hidden)]
    pub fn selected_macro_head_bridge(
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

    #[doc(hidden)]
    pub fn selected_macro_head_definition(
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
            )
            .with_root_import_activation(path.root_import_activation());
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_for_test(
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
    DeclaredHead { start: usize, end: usize },
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
    // An end checkpoint rebuilds the preceding chain without expired routes.
    // Each insertion is replayed at these snapshot nodes, retaining its own
    // source-position choice and therefore its original precedence.
    snapshots: HashMap<usize, Vec<ActivationCheckpoint>>,
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
    activation_ends: &HashMap<ResolutionScopeId, HashSet<usize>>,
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
                        snapshots: HashMap::default(),
                    },
                )
                .is_none()
        );
    }

    let mut paths = Vec::new();
    for timeline in timelines.values_mut() {
        let mut previous = timeline.head;
        for checkpoint in &timeline.checkpoints {
            if activation_ends
                .get(&timeline.fact.id)
                .is_some_and(|ends| ends.contains(&checkpoint.position))
            {
                previous = timeline.head;
                for insertion in &timeline.checkpoints {
                    if insertion.position >= checkpoint.position {
                        break;
                    }
                    let digest = local_digest(
                        b"bifrost-resolution-activation-snapshot:v1",
                        &[
                            ("scope", &u32_bytes(timeline.fact.id.get())),
                            ("insertion", &usize_bytes(insertion.position)),
                            ("snapshot", &usize_bytes(checkpoint.position)),
                        ],
                    );
                    let node = identities.node(ResolutionNodeIdentity::new(digest));
                    nodes.push((node, BindingNodeKind::Scope));
                    timeline
                        .snapshots
                        .entry(insertion.position)
                        .or_default()
                        .push(ActivationCheckpoint {
                            position: checkpoint.position,
                            node,
                        });
                    let id = identities.path(ResolutionPathIdentity::new(digest));
                    let variable = passthrough_variable(identities, id);
                    paths.push((
                        id,
                        PartialPath::new(
                            open_endpoint(node, variable),
                            open_endpoint(previous, variable),
                            precedence_rules(language)
                                .continuation_precedence(
                                    identities,
                                    timeline.fact.id,
                                    Some(insertion.position),
                                )
                                .unwrap_or_else(|| {
                                    checkpoint_fallback_precedence(
                                        identities,
                                        timeline.fact.id,
                                        insertion.position,
                                    )
                                }),
                            [WitnessStep::Node(previous)],
                            ResolutionCompletion::Complete,
                        ),
                    ));
                    previous = node;
                }
            }
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
                    precedence_rules(language)
                        .continuation_precedence(
                            identities,
                            timeline.fact.id,
                            Some(checkpoint.position),
                        )
                        .unwrap_or_else(|| {
                            checkpoint_fallback_precedence(
                                identities,
                                timeline.fact.id,
                                checkpoint.position,
                            )
                        }),
                    [WitnessStep::Node(previous)],
                    ResolutionCompletion::Complete,
                ),
            ));
            previous = checkpoint.node;
        }
    }
    for timeline in timelines.values() {
        // A scope the producer marked as a lookup root keeps its parent link,
        // which placement and containment still read, but contributes no
        // outward lexical path: a name this scope does not declare is not
        // found by continuing into the parent's timeline. The producer is the
        // only authority on which of its scopes are roots
        // (`ResolutionScopeInheritance`), and the lowering reads the flag
        // without asking which language wrote it.
        if let Some(parent) = index.lookup_scope_parent(timeline.fact.id) {
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
                    if let Some(steps) = precedence_rules(language).continuation_precedence(
                        identities,
                        timeline.fact.id,
                        None,
                    ) {
                        steps
                    } else if timeline.fact.kind == ResolutionScopeKind::TypeBody {
                        type_body_enclosing_precedence(identities, timeline.fact.id)
                    } else if let Some(namespaces) =
                        precedence_rules(language).scope_choice_namespaces()
                    {
                        scope_choice_outward_precedence(identities, timeline.fact.id, namespaces)
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
/// about. Catalogs belong to the calling fixture thread: concurrent fixtures
/// may reuse one fragment ordinal while lowering different facts. Nothing
/// here exists outside tests or the test-support feature.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod fixture_names {
    use super::super::local_identity::ResolutionIdentityCatalog;
    use super::*;
    use crate::hash::HashMap;
    use std::cell::RefCell;

    std::thread_local! {
        static CATALOGS: RefCell<HashMap<u32, std::sync::Arc<ResolutionIdentityCatalog>>> =
            RefCell::new(HashMap::default());
        static SELECTED_CONTENT: RefCell<HashMap<u32, [u8; 32]>> = RefCell::new(HashMap::default());
    }

    #[doc(hidden)]
    pub fn record_selected(catalog: &ResolutionIdentityCatalog, content: [u8; 32]) {
        record(catalog);
        SELECTED_CONTENT.with(|contents| {
            contents
                .borrow_mut()
                .insert(catalog.fragment().ordinal(), content);
        });
    }

    fn fragment_content(ordinal: u32) -> Option<[u8; 32]> {
        SELECTED_CONTENT
            .with(|contents| contents.borrow().get(&ordinal).copied())
            .or_else(|| super::super::model::fixture_label_digest(u64::from(ordinal)))
    }

    #[doc(hidden)]
    pub fn record(catalog: &ResolutionIdentityCatalog) {
        SELECTED_CONTENT.with(|contents| {
            contents.borrow_mut().remove(&catalog.fragment().ordinal());
        });
        CATALOGS.with(|catalogs| {
            catalogs.borrow_mut().insert(
                catalog.fragment().ordinal(),
                std::sync::Arc::new(catalog.clone()),
            );
        });
    }

    fn catalog(fragment: BindingFragmentId) -> std::sync::Arc<ResolutionIdentityCatalog> {
        CATALOGS
            .with(|catalogs| catalogs.borrow().get(&fragment.ordinal()).cloned())
            .unwrap_or_else(|| {
                panic!("no fixture lowered {fragment}, so nothing numbered its identities")
            })
    }

    pub(crate) fn identity_content_digest(
        key: super::super::ResolutionIdentityDigestKey,
    ) -> Option<[u8; 32]> {
        use super::super::model::fixture_label_digest;
        use super::super::{
            ResolutionIdentityDigestKey as Key, SharedNameInterner, mounted_identity_digest,
        };
        let (ordinal, kind, digest) = match key {
            Key::Fragment(fragment) => return fragment_content(fragment.ordinal()),
            Key::Semantic(semantic) => {
                if let Some(name) = semantic.shared_name_id() {
                    return CATALOGS
                        .with(|catalogs| {
                            catalogs.borrow().values().find_map(|catalog| {
                                catalog
                                    .semantic_coordinate(semantic)
                                    .map(|(_, identity)| catalog.identity_hash_bytes(identity))
                            })
                        })
                        .or_else(|| {
                            super::super::local_identity::test_shared_names().digest_for_id(name)
                        });
                }
                if let Some(number) = semantic.operation_local_number() {
                    return fixture_label_digest(
                        number & !super::super::model::FIXTURE_OPERATION_BASE,
                    );
                }
                let ordinal = semantic.ordinal()?;
                let catalog = CATALOGS.with(|catalogs| catalogs.borrow().get(&ordinal).cloned())?;
                let (_, identity) = catalog.semantic_coordinate(semantic)?;
                (
                    ordinal,
                    b"semantic".as_slice(),
                    identity.fragment_local_digest(),
                )
            }
            Key::Node(node) => {
                if node == BindingNodeId::universal_root() {
                    return Some(
                        brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                            b"bifrost-resolution-universal-root:v1",
                            &[],
                        ),
                    );
                }
                if let Some(number) = node.operation_local_number() {
                    return fixture_label_digest(
                        number & !super::super::model::FIXTURE_OPERATION_BASE,
                    );
                }
                let ordinal = node.ordinal()?;
                let catalog = CATALOGS.with(|catalogs| catalogs.borrow().get(&ordinal).cloned())?;
                let (_, identity) = catalog.node_coordinate(node)?;
                (ordinal, b"node".as_slice(), identity.digest())
            }
            Key::Path(path) => {
                if let Some(number) = path.operation_local_number() {
                    return fixture_label_digest(
                        number & !super::super::model::FIXTURE_OPERATION_BASE,
                    );
                }
                let ordinal = path.ordinal()?;
                let catalog = CATALOGS.with(|catalogs| catalogs.borrow().get(&ordinal).cloned())?;
                let (_, identity) = catalog
                    .paths()
                    .iter()
                    .find(|(runtime, _)| *runtime == path)?;
                (
                    ordinal,
                    b"path".as_slice(),
                    if i64::from(path.local_key()?)
                        < super::super::local_identity::SUPPLEMENTAL_LOCAL_KEY_BASE
                    {
                        brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                            b"bifrost-resolution-published-path-position:v1",
                            &path.local_key()?.to_be_bytes(),
                        )
                    } else {
                        identity.digest()
                    },
                )
            }
        };
        Some(mounted_identity_digest(
            kind,
            fragment_content(ordinal)?,
            digest,
        ))
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
    #[doc(hidden)]
    pub struct FixtureRootImportAnchors;

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
            let Some(catalog) = CATALOGS.with(|catalogs| catalogs.borrow().get(&ordinal).cloned())
            else {
                return Ok(None);
            };
            let Some(identity) = catalog.semantic_identity(semantic) else {
                return Ok(None);
            };
            Ok(super::root_import_anchor_for_identity(&identity))
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

    #[doc(hidden)]
    pub fn reference_semantic(fragment: BindingFragmentId, site: ResolutionSiteId) -> SemanticId {
        mounted_site_semantic(fragment, site)
    }

    #[doc(hidden)]
    pub fn definition_node(fragment: BindingFragmentId, site: ResolutionSiteId) -> BindingNodeId {
        mounted_site_node(fragment, site)
    }

    #[doc(hidden)]
    pub fn reference_node(fragment: BindingFragmentId, site: ResolutionSiteId) -> BindingNodeId {
        mounted_site_node(fragment, site)
    }

    macro_rules! fixture_name {
        ($visibility:vis $name:ident, $identity:path, $of:ident, $result:ty $(, $argument:ident : $type:ty)*) => {
            #[doc(hidden)]
            $visibility fn $name(
                fragment: BindingFragmentId
                $(, $argument: $type)*
            ) -> $result {
                $of(fragment, $identity($($argument),*))
            }
        };
    }

    fixture_name!(pub scope_head_node, scope_head_node_identity, node_of, BindingNodeId,
        scope: ResolutionScopeId);
    fixture_name!(pub(crate) checkpoint_node, super::checkpoint_node_identity, node_of, BindingNodeId,
        scope: ResolutionScopeId, position: usize);
    fixture_name!(pub(crate) gap_sink_node, super::gap_sink_node_identity, node_of, BindingNodeId,
        site: ResolutionSiteId, role: &[u8]);
    fixture_name!(pub(crate) structured_import_gap_sink_node, super::structured_import_gap_sink_node_identity,
        node_of, BindingNodeId, site: ResolutionSiteId, namespace: ResolutionNamespace);

    fixture_name!(pub(crate) type_slot_semantic, super::type_slot_semantic_identity, semantic_of, SemanticId,
        slot: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId);
    fixture_name!(pub site_type_frontier_semantic, super::site_type_frontier_semantic_identity,
        semantic_of, SemanticId, site: ResolutionSiteId);
    fixture_name!(pub gap_reason_semantic, super::gap_reason_semantic_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, origin: LoweringGapOrigin);
    fixture_name!(pub root_export_token, root_export_token_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(pub root_import_token, root_import_token_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(pub root_reference_token, root_reference_token_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(pub root_import_anchor_semantic, root_import_anchor_semantic_identity, semantic_of,
        SemanticId,
        anchor: brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor);
    fixture_name!(pub scope_choice, super::scope_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(pub(crate) hierarchy_choice, super::hierarchy_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(pub(crate) checkpoint_choice, super::checkpoint_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, position: usize, namespace: ResolutionNamespace);

    fixture_name!(pub(crate) binder_path_id, super::binder_path_identity, path_of, PartialPathId,
        site: ResolutionSiteId);
    fixture_name!(pub(crate) hierarchy_gap_path_id, super::hierarchy_gap_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, owner: ResolutionSiteId);
    fixture_name!(pub additional_binder_path_id, super::additional_binder_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(pub(crate) placement_gap_path_id, super::placement_gap_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, scope: ResolutionScopeId);
    fixture_name!(pub(crate) root_export_path_id, super::root_export_path_identity, path_of, PartialPathId,
        scope: ResolutionScopeId, declaration: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(pub(crate) root_import_path_id, super::root_import_path_identity, path_of, PartialPathId,
        site: ResolutionSiteId, namespace: ResolutionNamespace,
        name: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId);
    fixture_name!(pub(crate) root_reference_path_id, super::root_reference_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(pub(crate) parent_path_id, super::parent_path_identity, path_of, PartialPathId,
        scope: ResolutionScopeId);
    fixture_name!(pub(crate) missing_binder_path_id, super::missing_binder_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId);
    fixture_name!(pub(crate) reference_path_id, super::reference_path_identity, path_of, PartialPathId,
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
#[doc(hidden)]
pub fn lower_lexical_for_test(
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
#[doc(hidden)]
pub fn lower_for_test(
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
    require_catalog_position(catalog.semantic_for_identity(identity), identity)
}

/// The runtime node one fixture's catalog gives a producer identity. See
/// [`catalog_semantic`].
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn catalog_node(
    catalog: &super::local_identity::ResolutionIdentityCatalog,
    identity: ResolutionNodeIdentity,
) -> BindingNodeId {
    require_catalog_position(catalog.node_for_identity(identity), identity)
}

fn require_catalog_position<T>(position: Option<T>, identity: impl std::fmt::Debug) -> T {
    position.unwrap_or_else(|| panic!("the fixture's catalog has no position for {identity:?}"))
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
    let index = FactIndex::new(language, facts);
    let call_callees = facts
        .calls
        .iter()
        .map(|call| call.callee)
        .collect::<HashSet<_>>();
    index.validate_scope_forest();

    let applicability_selects_callee =
        crate::analyzer::semantic::languages::language_knowledge(language)
            .expect("resolution facts require registered language knowledge")
            .call_applicability_may_select_callee();
    let mut gap_sources = facts
        .gaps
        .iter()
        .filter(|gap| {
            // Typed lowering reads the original facts and retains the call
            // obligation's reason. Indirect callees without reference identifiers
            // have no such obligation and must keep their type coverage.
            applicability_selects_callee
                || gap.kind != ResolutionGapKind::UnsupportedCallApplicability
                || !call_callees.contains(&gap.site)
                || !index
                    .identifiers_by_site
                    .get(&gap.site)
                    .is_some_and(|identifiers| {
                        identifiers.iter().any(|identifier| {
                            identifier.role == ResolutionIdentifierRole::Reference
                        })
                    })
        })
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
    let mut activation_ends: HashMap<ResolutionScopeId, HashSet<usize>> = HashMap::default();
    let mut declarations_with_binders = HashSet::default();
    let alias_sites = facts
        .binders
        .iter()
        .filter_map(|binder| {
            matches!(binder.kind, ResolutionBinderKind::Alias { .. }).then_some(binder.declaration)
        })
        .collect::<HashSet<_>>();
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
        let identifier = if let ResolutionBinderKind::Alias { target } = binder.kind {
            assert!(
                !alias_sites.contains(&target),
                "an alias target must not be an alias binder: {binder:?}"
            );
            // This lookup asserts both fragment membership and declaration role.
            let target_identifier = index.declaration_identifier(target);
            let alias = index.identifier(binder.declaration);
            assert_eq!(declaration.kind, ResolutionSiteKind::AliasBinding);
            assert_eq!(alias.role, ResolutionIdentifierRole::Alias);
            assert_eq!(
                index.name(alias.name),
                index.name(target_identifier.name),
                "alias and target must spell the same name"
            );
            assert_eq!(
                alias.namespace, target_identifier.namespace,
                "alias and target must occupy the same namespace"
            );
            assert!(alias.qualifier.is_none(), "an alias is unqualified");
            alias
        } else {
            index.declaration_identifier(binder.declaration)
        };
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
            HoistingClass::DeclaredHead => {
                activation_positions
                    .entry(binder.scope)
                    .or_default()
                    .push(binder.activation_start);
                if binder.activation_end < scope.end_byte {
                    activation_positions
                        .entry(binder.scope)
                        .or_default()
                        .push(binder.activation_end);
                    activation_ends
                        .entry(binder.scope)
                        .or_default()
                        .insert(binder.activation_end);
                }
                Some(SupportedActivation::DeclaredHead {
                    start: binder.activation_start,
                    end: binder.activation_end,
                })
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

    // A positioned import takes effect at its position, like a source-order
    // binder, so its scope needs a checkpoint there.
    for import in &facts.root_imports {
        let Some(position) = import.position else {
            continue;
        };
        let scope = index.scope(import.root_scope);
        // Position is producer-owned activation syntax, independent of language.

        assert!(
            scope.start_byte <= position && position <= scope.end_byte,
            "a positioned import takes effect inside its root scope: {import:?}, {scope:?}"
        );
        activation_positions
            .entry(import.root_scope)
            .or_default()
            .push(position);
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
        assert!(
            index.site(module).kind == ResolutionSiteKind::ModuleDeclaration
                && !declarations_with_binders.contains(&module),
            "a route-owned module is a module declaration with no binder: {module:?}"
        );
    }
    let slot_authored_declarations = facts
        .binding_events
        .iter()
        .filter_map(|event| event.authored_declaration)
        .collect::<HashSet<_>>();
    for identifier in &facts.identifiers {
        if identifier.role == ResolutionIdentifierRole::Declaration
            // A canonical slot owns the lexical route; its authored callable
            // or type declaration is a source/value origin, not another binder.
            && !slot_authored_declarations.contains(&identifier.site)
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
        if identifier.role == ResolutionIdentifierRole::Reference
            && identifier.qualifier.is_some()
            && !(root_prefix_rule(language)
                .is_some_and(|rule| rule.terminal_namespace == Some(identifier.namespace))
                && index.root_reference(identifier.site).is_some())
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
    } = lower_scope_timelines_and_paths(
        identities,
        language,
        &index,
        &activation_positions,
        &activation_ends,
    );

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
        let support = crate::analyzer::store::store_language_support_for_hook(
            language,
            "go_member_definition_namespaces",
        )
        .expect("Go resolution has language support");
        let member_declarations = facts
            .member_owners
            .iter()
            .filter(|owner| {
                support
                    .go_member_definition_namespaces(owner.kind)
                    .is_some()
            })
            .map(|owner| owner.member)
            .collect::<HashSet<_>>();
        for binder in &supported_binders {
            if member_declarations.contains(&binder.fact.declaration)
                || !matches!(
                    binder.fact.kind,
                    ResolutionBinderKind::Type
                        | ResolutionBinderKind::Local
                        | ResolutionBinderKind::Parameter
                        | ResolutionBinderKind::Callable
                )
            {
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
    // The schema numbers a site, its semantic and its node with one integer,
    // which requires each site to carry exactly one role. Every producer follows
    // this same rule.
    let mut role_by_site: HashMap<ResolutionSiteId, LoweredSemanticRole> = HashMap::default();
    for identifier in index.identifiers_sorted() {
        let site = index.site(identifier.site);
        let (role, semantic, node, kind) = match identifier.role {
            ResolutionIdentifierRole::Alias => continue,
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
                        && !index.suppresses_lexical_lookup(identifier.site),
                    index.reference_owner(identifier.site).map(|owner| {
                        owner.map(|owner| identities.source_definition_semantic(owner))
                    }),
                    index.receiver_origin(identifier.site),
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

    // Nameless declarations own source bodies without inventing a lexical
    // name. Languages declare their namespace through structured authority.
    let mut anonymous = index
        .anonymous_callables
        .iter()
        .map(|&site| (site, ResolutionNamespace::Callable))
        .chain(
            route_owned_modules
                .iter()
                .filter(|site| !index.identifiers_by_site.contains_key(*site))
                .map(|&site| {
                    let namespaces = &index.additional_definition_namespaces_by_declaration[&site];
                    assert_eq!(namespaces.len(), 1, "one nameless module namespace");
                    (site, namespaces[0].namespace)
                }),
        )
        .collect::<Vec<_>>();
    anonymous.sort_unstable();
    for (site, namespace) in anonymous {
        let semantic = identities.source_definition_semantic(site);
        let node = identities.source_definition_node(site);
        assert!(
            role_by_site
                .insert(site, LoweredSemanticRole::Definition)
                .is_none()
        );
        assert!(
            semantic_by_site
                .insert((site, LoweredSemanticRole::Definition), (semantic, node))
                .is_none()
        );
        semantics.push(LoweredSemanticSite::new(
            site,
            namespace,
            LoweredSemanticRole::Definition,
            semantic,
            node,
            None,
        ));
        nodes.push((node, BindingNodeKind::Definition(semantic)));
    }

    // Alias uncertainty cannot weaken the authored source declaration or its
    // ordinary type. It belongs to the separate JVM alias surface.
    let source_gap_sources = gap_sources
        .iter()
        .copied()
        .filter(|source| {
            source.origin != LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute)
                || !index.route_gaps_by_site.get(&source.site).into_iter().flatten().any(|route| {
                    matches!(*route, ResolutionRouteGap::UnknownAlias { owner, .. } if !matches!(owner, ResolutionRouteOwner::DeclarationAccess(_)))
                })
        })
        .collect::<Vec<_>>();
    let reasons_by_site = gap_reasons_by_site(identities, &source_gap_sources);
    let mut forward_gap_endpoints = HashMap::default();
    let owner_references = facts
        .lexical_owner_references
        .iter()
        .map(|fact| (fact.reference, fact.declaration))
        .collect::<HashMap<_, _>>();
    assert_eq!(
        owner_references.len(),
        facts.lexical_owner_references.len(),
        "one structural owner per qualifier reference: {:?}",
        facts.lexical_owner_references
    );

    for semantic in semantics
        .iter()
        .filter(|semantic| semantic.role == LoweredSemanticRole::Reference)
    {
        let identifier = index.reference_identifier(semantic.site);
        let site = index.site(semantic.site);
        let completion = completion_for_site(&reasons_by_site, semantic.site, |origin| {
            index.lexical_reference_gap(semantic.site, origin)
        });
        if let Some(&owner) = owner_references.get(&semantic.site) {
            let (target, required) = if let Some(owner) = owner {
                let (_, target) = semantic_by_site[&(owner, LoweredSemanticRole::Definition)];
                (target, Vec::new())
            } else {
                assert!(matches!(&completion, ResolutionCompletion::Incomplete(_)));
                let sink = identities.node(gap_sink_node_identity(
                    semantic.site,
                    b"lexical-owner-unavailable",
                ));
                nodes.push((sink, BindingNodeKind::Scope));
                let lookup = identities.lookup_semantic(
                    language,
                    identifier.namespace,
                    index.name(identifier.name),
                );
                (sink, vec![lookup])
            };
            let id = identities.path(reference_path_identity(semantic.site, identifier.namespace));
            paths.push((
                id,
                PartialPath::new(
                    closed_endpoint(semantic.node, []),
                    closed_endpoint(target, required),
                    Vec::new(),
                    [WitnessStep::Node(target)],
                    completion,
                ),
            ));
            continue;
        }
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
        if index.suppresses_lexical_lookup(identifier.site) {
            // A root-qualified reference has an explicit source-owned route.
            // Its terminal semantic remains ordinary, but it must not also
            // publish a lexical route that could close through a local decoy.
            continue;
        }
        if identifier.qualifier.is_some() {
            let scoped_extension_receiver_call =
                super::fact_resolution::call_applicability::adapter(language)
                    .has_scoped_receiver_extensions()
                    && semantic.callable_receiver_origin()
                        == Some(ResolutionCallableReceiverOrigin::ExplicitExpression);
            if scoped_extension_receiver_call {
                // Receiver extensions are lexically visible callables,
                // not declarations in the receiver's member scope. Preserve a
                // separate lexical candidate path for the shared member
                // lookup hook; qualified replay continues to search members.
                let timeline = timelines
                    .get(&site.scope)
                    .expect("qualified call scope has a timeline");
                let checkpoint = timeline.active_node_at(site.start_byte);
                let lookup = identities.lookup_semantic(
                    language,
                    ResolutionNamespace::Callable,
                    index.name(identifier.name),
                );
                let path = identities.path(reference_path_identity(
                    semantic.site,
                    ResolutionNamespace::Callable,
                ));
                let lexical_completion =
                    completion_for_site(&reasons_by_site, semantic.site, |origin| {
                        origin != LoweringGapOrigin::QualifiedReference
                            && index.lexical_reference_gap(semantic.site, origin)
                    });
                paths.push((
                    path,
                    PartialPath::new(
                        closed_endpoint(semantic.node, []),
                        closed_endpoint(checkpoint, [lookup]),
                        Vec::new(),
                        [WitnessStep::Node(checkpoint)],
                        lexical_completion,
                    ),
                ));
            }
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
        let call_target_routes =
            call_target_lookup_routes(language, call_callees.contains(&semantic.site));
        let routes = if go_spelling {
            &go_routes[..]
        } else {
            call_target_routes
                .unwrap_or_else(|| lexical_lookup_routes(language, identifier.namespace))
        };
        for &(route_ordinal, namespace) in routes {
            let lookup =
                identities.lookup_semantic(language, namespace, index.name(identifier.name));
            let precedence = (!go_spelling
                && (identifier.namespace == ResolutionNamespace::TypeOrValue
                    || call_target_routes.is_some()))
            .then(|| {
                identities.register_precedence_namespace(
                    PrecedenceStep {
                        tier: PrecedenceTier::LexicalBinding,
                        ordinal: route_ordinal,
                        semantic: semantic.semantic,
                    },
                    call_target_routes.map_or(namespace, |routes| {
                        call_target_choice_namespace(routes, route_ordinal)
                    }),
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
    let mut routed_binder_sites = HashSet::default();
    let mut alias_gap_endpoints = Vec::new();
    for binder in supported_binders {
        let timeline = timelines
            .get(&binder.fact.scope)
            .expect("validated binder scope has a timeline");
        let checkpoint = match binder.activation {
            SupportedActivation::ScopeWide => timeline.head,
            SupportedActivation::SourceOrder(position)
            | SupportedActivation::DeclaredHead {
                start: position, ..
            } => {
                let checkpoint = timeline.checkpoint_at(position);
                checkpoint.node
            }
        };
        let target = match binder.fact.kind {
            ResolutionBinderKind::Alias { target } => target,
            _ => binder.fact.declaration,
        };
        let (_definition, definition_node) = semantic_by_site
            .get(&(target, LoweredSemanticRole::Definition))
            .copied()
            .expect("binder declaration has a definition semantic");
        let mut gap_endpoints = vec![checkpoint];
        let activation_start = match binder.activation {
            SupportedActivation::ScopeWide => None,
            SupportedActivation::SourceOrder(start)
            | SupportedActivation::DeclaredHead { start, .. } => Some(start),
        };
        if let Some(start) = activation_start {
            gap_endpoints.extend(timeline.snapshots.get(&start).into_iter().flatten().filter(|snapshot| {
                !matches!(binder.activation, SupportedActivation::DeclaredHead { end, .. } if snapshot.position >= end)
            }).map(|snapshot| snapshot.node));
        }
        assert!(
            routed_binder_sites.insert(binder.fact.declaration),
            "one supported binder route per declaration or alias site is required"
        );
        if target == binder.fact.declaration {
            assert!(
                forward_gap_endpoints
                    .insert(target, gap_endpoints)
                    .is_none()
            );
        } else {
            alias_gap_endpoints.push((target, gap_endpoints));
        }
        let binding_completion = completion_for_site(
            &reasons_by_site,
            binder.fact.declaration,
            lexical_declaration_gap,
        );
        let binding_completion = if target != binder.fact.declaration {
            binding_completion.combine(&completion_for_site(
                &reasons_by_site,
                target,
                lexical_declaration_gap,
            ))
        } else {
            binding_completion
        };
        let primary_namespace = effective_declaration_namespace(binder.identifier.namespace);
        let value_alias = index.value_aliased_callables.contains(&target);
        let namespaces = std::iter::once(primary_namespace)
            .chain(
                index
                    .additional_definition_namespaces(target)
                    .iter()
                    .map(|fact| fact.namespace)
                    .filter(|namespace| *namespace != primary_namespace),
            )
            .chain(value_alias.then_some(ResolutionNamespace::Value));
        for namespace in namespaces {
            if matches!(binder.activation, SupportedActivation::DeclaredHead { start, end } if start == end)
            {
                continue;
            }
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
                                SupportedActivation::SourceOrder(position)
                                | SupportedActivation::DeclaredHead {
                                    start: position, ..
                                } => Some(position),
                            },
                            if binder.superseded { 2 } else { 0 },
                        )
                    } else {
                        // The Value alias of a callable ranks in the Value
                        // namespace, so a val of the same scope outranks it.
                        // Every other path keeps the declaration's own.
                        let choice_namespace =
                            if value_alias && namespace == ResolutionNamespace::Value {
                                ResolutionNamespace::Value
                            } else {
                                primary_namespace
                            };
                        binder_precedence(identities, language, timeline, &binder, choice_namespace)
                    },
                    [WitnessStep::Node(definition_node)],
                    binding_completion.clone(),
                ),
            ));
            let activation_start = match binder.activation {
                SupportedActivation::ScopeWide => continue,
                SupportedActivation::SourceOrder(start)
                | SupportedActivation::DeclaredHead { start, .. } => start,
            };
            for snapshot in timeline
                .snapshots
                .get(&activation_start)
                .into_iter()
                .flatten()
            {
                if matches!(binder.activation, SupportedActivation::DeclaredHead { end, .. } if snapshot.position >= end)
                {
                    continue;
                }
                let precedence = paths
                    .last()
                    .expect("binder path just published")
                    .1
                    .precedence()
                    .to_vec();
                let replay_id =
                    identities.path(activation_replay_path_identity(identity, snapshot.position));
                paths.push((
                    replay_id,
                    PartialPath::new(
                        closed_endpoint(snapshot.node, [lookup]),
                        closed_endpoint(definition_node, []),
                        precedence,
                        [WitnessStep::Node(definition_node)],
                        binding_completion.clone(),
                    ),
                ));
            }
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
            || index.anonymous_callables.contains(&semantic.site)
            || (route_owned_modules.contains(&semantic.site)
                && !index.identifiers_by_site.contains_key(&semantic.site))
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
                .insert(semantic.site, vec![timeline.head])
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

    for (target, endpoints) in alias_gap_endpoints {
        forward_gap_endpoints
            .entry(target)
            .or_default()
            .extend(endpoints);
    }
    lower_root_import_paths(
        identities,
        language,
        &index,
        &reasons_by_site,
        &timelines,
        &mut nodes,
        &mut paths,
    );
    lower_root_reference_paths(
        identities,
        language,
        &index,
        &call_callees,
        &reasons_by_site,
        &mut paths,
    );
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
            let timeline = timelines
                .get(&import.root_scope)
                .expect("validated import root has a timeline");
            for &namespace in single_import_namespaces(import.kind) {
                let bound_name = import
                    .bound_name
                    .expect("single-name import has a bound name");
                let (sink, row) = structured_import_gap_lexical_row_with_identities(
                    identities,
                    language,
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
            if !package_lookups_cover_placement(language, facts, &index, source.site, scope.id) {
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
            hierarchy_terminals.push((identities.gap_reason(source.site, source.origin), sink));
            nodes.push((sink, BindingNodeKind::Scope));
            let reason = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(
                    identities.gap_reason(source.site, source.origin),
                ),
            ]);
            let interface_members = index
                .implicit_interface_member_references
                .contains(&source.site);
            if index.is_implicit_superclass_reference(source.site) || interface_members {
                // The implicit superclass is java.lang.Object, whose members
                // JLS 4.3.2 fixes: methods only. Only a callable lookup of one
                // of its method names can reach this unindexed edge, so the
                // branch is closed on exactly those lookups; member-type,
                // field and constructor lookups never meet it.
                let member_names = if interface_members {
                    brokk_bifrost_jvm::intrinsics::implicit_interface_members(language)
                        .expect("a producer member-root edge requires a language rule")
                        .methods
                        .iter()
                        .map(|method| method.name)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    language_implicit_root_member_names(Language::Java).to_vec()
                };
                for name in member_names {
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

    let closed_macro_member_surfaces = facts
        .engine_rule_eligibilities
        .iter()
        .filter(|fact| fact.rule == ResolutionEngineRuleKind::ClosedMacroMemberSurface)
        .map(|fact| fact.site)
        .collect::<HashSet<_>>();
    for (scope, sources) in unexpanded_item_macros {
        lower_unexpanded_item_macro_branches(
            identities,
            &index,
            scope,
            &sources,
            &closed_macro_member_surfaces,
            &mut nodes,
            &mut paths,
        );
    }

    let mut alias_surfaces = facts
        .gaps
        .iter()
        .flat_map(|gap| match gap.route() {
            Some(ResolutionRouteGap::UnknownAlias {
                owner,
                binary_owner,
                kind,
                ..
            }) if !matches!(owner, ResolutionRouteOwner::DeclarationAccess(_)) => {
                alias_gap_namespaces(kind)
                    .iter()
                    .map(|&namespace| {
                        alias_route_surface_node_identity(&binary_owner, &index, namespace)
                    })
                    .collect::<Vec<_>>()
            }
            _ => Vec::new(),
        })
        .collect::<Vec<_>>();
    alias_surfaces.sort_unstable_by_key(|identity| identity.digest());
    alias_surfaces.dedup();
    for surface in alias_surfaces {
        nodes.push((identities.node(surface), BindingNodeKind::Scope));
    }

    let mut gaps = lower_coverage_gaps(
        identities,
        language,
        facts,
        GapCoverageSources {
            all: &coverage_gap_sources,
            point: &point_gap_sources,
            enumeration: &reference_enumeration_sources,
            deferred_members: &deferred_member_declarations,
            facts,
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
    reasons_by_site: &HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>>,
    timelines: &HashMap<ResolutionScopeId, ScopeTimeline>,
    nodes: &mut Vec<(BindingNodeId, BindingNodeKind)>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    for import in &index.root_imports {
        // A scope-wide import starts at the scope's head and ranks on the
        // scope's choice. A positioned import starts at its checkpoint and
        // ranks on that checkpoint's choice, so it shadows what the scope
        // continues to and what earlier checkpoints reach, and nothing
        // written before it sees it.
        let checkpoint = import.fact.position.map(|position| {
            timelines
                .get(&import.fact.root_scope)
                .expect("a validated root import scope has a timeline")
                .checkpoint_at(position)
        });
        let source_scope_head = identities.source_scope_node(import.fact.root_scope);
        let start = checkpoint.map_or(source_scope_head, |checkpoint| checkpoint.node);
        let witness = if import.fact.position.is_some() {
            [
                WitnessStep::Node(source_scope_head),
                WitnessStep::Node(BindingNodeId::universal_root()),
            ]
            .into_iter()
            .collect::<Vec<_>>()
        } else {
            vec![WitnessStep::Node(BindingNodeId::universal_root())]
        };
        let mut routes_by_namespace = HashMap::default();
        let structured_bound_name = index
            .structured_import(import.fact.site)
            .and_then(|route| route.bound_name);
        let open_destination = index.structured_import(import.fact.site).is_some()
            && index
                .route_gaps_by_site
                .get(&import.fact.site)
                .into_iter()
                .flatten()
                .any(|route| {
                    matches!(
                        route,
                        ResolutionRouteGap::UnknownBinder {
                            may_publish: false,
                            ..
                        }
                    )
                });
        let mut gap_namespaces = HashSet::default();
        for demand in &import.demands {
            // The route traverses the imported source name, but its local
            // endpoint is selected by the name bound in the importing scope.
            // Keep the path key aligned with that endpoint so a later lookup
            // by an aliased name can enter this route.
            let route_name = structured_bound_name.unwrap_or(demand.name);
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
                identities.lookup_semantic(language, demand.namespace, index.name(route_name));
            let token = identities.semantic(root_import_token_identity(
                import.fact.site,
                demand.namespace,
            ));
            let id = identities.path(root_import_path_identity(
                import.fact.site,
                demand.namespace,
                route_name,
            ));
            let tail = passthrough_variable(identities, id);
            let mut root_symbols = Vec::with_capacity(route.len().saturating_add(3));
            root_symbols.push(
                identities.semantic(root_import_anchor_semantic_identity(import.fact.anchor)),
            );
            root_symbols.extend(route);
            root_symbols.push(token);
            root_symbols.push(lookup);
            let choice = identities.semantic(match import.fact.position {
                Some(position) => {
                    checkpoint_choice_identity(import.fact.root_scope, position, demand.namespace)
                }
                None => scope_choice_identity(import.fact.root_scope, demand.namespace),
            });
            // The producer's byte position orders positional imports within
            // their blob. Other languages supply none, so their rows store NULL.
            let activation = import.fact.position.map(|position| {
                u32::try_from(position).expect("a root import position fits a source offset")
            });
            // A structured wildcard has a known route, not an unknown
            // binder at the scope head. Its destination can only compete at
            // this import's rank. Keep each demanded name and namespace on
            // the same branch so a nearer declaration can discharge it.
            if open_destination && import.kind == ResolutionRootImportKind::Glob {
                let sink = identities.node(structured_import_gap_sink_node_identity(
                    import.fact.site,
                    demand.namespace,
                ));
                if gap_namespaces.insert(demand.namespace) {
                    nodes.push((sink, BindingNodeKind::Scope));
                }
                let gap_id = identities.path(ResolutionPathIdentity::new(local_digest(
                    b"bifrost-resolution-root-import-destination-gap-path:v1",
                    &[(
                        "route",
                        &root_import_path_identity(import.fact.site, demand.namespace, route_name)
                            .digest(),
                    )],
                )));
                let reason = identities.gap_reason(
                    import.fact.site,
                    LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute),
                );
                paths.push((
                    gap_id,
                    PartialPath::new(
                        symbol_open_endpoint(start, [lookup], tail),
                        symbol_open_endpoint(sink, [lookup], tail),
                        root_import_precedence(
                            identities,
                            language,
                            import,
                            choice,
                            demand.namespace,
                        ),
                        [WitnessStep::Node(sink)],
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(reason),
                        ]),
                    )
                    .with_root_import_activation(activation),
                ));
            }
            paths.push((
                id,
                PartialPath::new(
                    symbol_open_endpoint(start, [lookup], tail),
                    symbol_open_endpoint(
                        BindingNodeId::universal_root(),
                        root_symbols.clone(),
                        tail,
                    ),
                    root_import_precedence(identities, language, import, choice, demand.namespace),
                    witness.clone(),
                    completion_for_site(reasons_by_site, import.fact.site, |origin| {
                        origin
                            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnprovenActivation)
                    }),
                )
                .with_root_import_activation(activation),
            ));
            if let Some(position) = import.fact.position {
                let timeline = &timelines[&import.fact.root_scope];
                for snapshot in timeline.snapshots.get(&position).into_iter().flatten() {
                    let replay_id = identities.path(activation_replay_path_identity(
                        root_import_path_identity(import.fact.site, demand.namespace, route_name),
                        snapshot.position,
                    ));
                    let tail = passthrough_variable(identities, replay_id);
                    paths.push((
                        replay_id,
                        PartialPath::new(
                            symbol_open_endpoint(snapshot.node, [lookup], tail),
                            symbol_open_endpoint(
                                BindingNodeId::universal_root(),
                                root_symbols.clone(),
                                tail,
                            ),
                            root_import_precedence(
                                identities,
                                language,
                                import,
                                choice,
                                demand.namespace,
                            ),
                            witness.clone(),
                            completion_for_site(reasons_by_site, import.fact.site, |origin| {
                                origin
                                    == LoweringGapOrigin::Extracted(
                                        ResolutionGapKind::UnprovenActivation,
                                    )
                            }),
                        ),
                    ));
                }
            }
        }
    }
}

/// A root import's rank at its scope's choice point.
///
/// Rust ranks a scope's imports above the scope's outward continuation, as
/// rustc does: a block's own items and imports, globs included, win over
/// every enclosing scope, and a named import wins over a glob. Both take the
/// continuation's rank on the scope choice and are ordered after it on the
/// scope's import choice (`scope_choice_outward_precedence`): named first, then
/// globs together with an unexpanded item macro's fallback branch
/// (`lower_unexpanded_item_macro_branches`), then the continuation. Java single
/// imports rank above on-demand imports at the same compilation-unit choice.
/// Scala and Kotlin named imports follow the same ordering; Kotlin implicit
/// imports are ranked separately by the selected JVM context. C# uses the
/// shared scope-choice form with aliases before usings, then outward lookup.
/// Other languages keep one wildcard-tier step, below their outward lookup.
fn root_import_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    import: &IndexedRootImport,
    choice: SemanticId,
    namespace: ResolutionNamespace,
) -> Vec<PrecedenceStep> {
    precedence_rules(language).root_import_steps(
        identities,
        &import.fact,
        import.kind,
        choice,
        namespace,
    )
}

fn precedence_rules(language: Language) -> &'static dyn super::precedence::PrecedenceRules {
    crate::analyzer::store::store_language_support_for_hook(language, "precedence_rules").map_or(
        &super::precedence::DefaultPrecedenceRules as &dyn super::precedence::PrecedenceRules,
        |support| support.precedence_rules(),
    )
}

pub(super) fn rust_root_import_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    import: &ResolutionRootImportFact,
    kind: ResolutionRootImportKind,
    choice: SemanticId,
    namespace: ResolutionNamespace,
) -> Vec<PrecedenceStep> {
    let import_choice = identities.semantic(import_choice_identity(import.root_scope, namespace));
    let import_token = identities.semantic(root_import_token_identity(import.site, namespace));
    // Rust's source-token guard lets selected cfg activation qualify the
    // following import-choice rank under the reference site's premise.
    let guard = precedence_step(import_token, 0);
    scope_choice_precedence(
        identities,
        choice,
        &[guard],
        import_choice,
        namespace,
        match kind {
            ResolutionRootImportKind::Named => ScopeChoice::MemberOrAlias,
            ResolutionRootImportKind::Glob => ScopeChoice::Import,
        },
    )
}

/// Assemble one scope level: the scope choice at ordinal 1, then the
/// language-supplied guard steps, then the import choice at ordinal 0 for a
/// member or alias, 1 for a use or import, or 2 for outward continuation.
/// Languages classify their bindings; named/glob choices use 0/1 respectively.
/// Inner scopes precede outer scopes on the path, so depth precedes origin.
pub fn scope_choice_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    choice: SemanticId,
    guards: &[PrecedenceStep],
    import_choice: SemanticId,
    namespace: ResolutionNamespace,
    binding: ScopeChoice,
) -> Vec<PrecedenceStep> {
    let mut steps = Vec::with_capacity(guards.len() + 2);
    steps.push(registered_precedence_step(identities, choice, 1, namespace));
    steps.extend(
        guards
            .iter()
            .map(|&step| identities.register_precedence_namespace(step, namespace)),
    );
    steps.push(registered_precedence_step(
        identities,
        import_choice,
        binding as u32,
        namespace,
    ));
    steps
}

/// A scope level's outward continuation: scope fallback precedes the last
/// import-choice rank, below the level's own bindings. The language supplies
/// the namespaces participating in that scope level.
pub fn scope_choice_outward_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
    namespaces: &[ResolutionNamespace],
) -> Vec<PrecedenceStep> {
    let mut steps = scope_fallback_precedence_for_namespaces(identities, scope, namespaces);
    for &namespace in namespaces {
        let semantic = identities.semantic(import_choice_identity(scope, namespace));
        steps.push(registered_precedence_step(
            identities,
            semantic,
            ScopeChoice::Outward as u32,
            namespace,
        ));
    }
    steps
}

/// The choice point shared by Rust and C# for members/aliases, imports
/// (including Rust item-macro fallback) and outward continuation, after they
/// tie on the scope choice. Its domain remains fragment-local.
pub fn import_choice_identity(
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(scope_namespace_digest(
        b"bifrost-resolution-import-choice-local:v1",
        "scope",
        scope,
        namespace,
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
    call_callees: &HashSet<ResolutionSiteId>,
    reasons_by_site: &HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    for reference in &index.root_references {
        let identifier = index.reference_identifier(reference.fact.reference);
        assert!(
            !reference.fact.owner_continued
                || (reference.fact.anchor == ResolutionRootImportAnchor::Lexical
                    && reference.fact.prefix_reference.is_none()
                    && reference.segments.is_empty()),
            "owner continuation marks only a lexical route head: {reference:?}, {identifier:?}"
        );
        let call_target_routes =
            call_target_lookup_routes(language, call_callees.contains(&reference.fact.reference));
        let rule = root_prefix_rule(language);
        assert!(
            identifier.namespace != ResolutionNamespace::TypeOrValue
                || (rule.is_some_and(
                    |rule| rule.terminal_namespace == Some(ResolutionNamespace::TypeOrValue)
                ) && (reference.fact.prefix_reference.is_some()
                    || (rule.is_some_and(|rule| rule.unprefixed_type_or_value)
                        && matches!(
                            reference.fact.anchor,
                            ResolutionRootImportAnchor::Absolute
                                | ResolutionRootImportAnchor::Lexical
                        )))),
            "only prefixed JVM or absolute/lexical Scala root references may retain type-or-value ambiguity: {reference:?}, {identifier:?}"
        );
        let (route_namespace, lookup_scope, prefix_reference) =
            if let Some(prefix_reference) = reference.fact.prefix_reference {
                let prefix_identifier = index.reference_identifier(prefix_reference);
                let Some(rule) = rule else {
                    panic!("positioned root prefixes are unsupported for {language:?}");
                };
                assert!(
                    rule.prefix_namespaces
                        .contains(&prefix_identifier.namespace),
                    "a {language:?} root prefix uses one of {:?}: {prefix_identifier:?}",
                    rule.prefix_namespaces
                );
                if rule.single_prefix_segment {
                    assert_eq!(
                        reference.segments.len(),
                        1,
                        "{language:?} selected continuation has one positioned qualifier"
                    );
                }
                (
                    rule.route_namespace,
                    index.site(prefix_reference).scope,
                    Some(identities.source_reference_semantic(prefix_reference)),
                )
            } else if (rule.is_some_and(|rule| rule.unprefixed_type_or_value)
                && reference.fact.anchor == ResolutionRootImportAnchor::Absolute)
                || call_target_routes.is_some()
            {
                (ResolutionNamespace::Type, reference.fact.root_scope, None)
            } else {
                (identifier.namespace, reference.fact.root_scope, None)
            };
        // Rust and Go continue from a resolved lexical prefix. JVM routes
        // retain the whole package spelling: their prefix is a shadowing
        // guard, and only an absent lexical type permits package interpretation.
        let route = reference
            .segments
            .iter()
            .skip(usize::from(
                prefix_reference.is_some() && rule.is_some_and(|rule| rule.consume_prefix_segment),
            ))
            .map(|&name| identities.lookup_semantic(language, route_namespace, index.name(name)))
            .collect::<Vec<_>>();
        for &(route_ordinal, namespace) in
            call_target_routes.unwrap_or_else(|| lookup_routes(identifier.namespace))
        {
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
            // Keep the whole Scala call-target ladder distinct from the
            // ordinary TypeOrValue ladder. Both ladders can occur in one
            // scope, but their ordinal 1 routes have different namespaces.
            let choice_namespace = if call_target_routes.is_some() {
                ResolutionNamespace::Callable
            } else if identifier.namespace == ResolutionNamespace::TypeOrValue {
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
            let precedence = vec![identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: route_ordinal,
                    semantic: choice,
                },
                call_target_routes.map_or(namespace, |routes| {
                    call_target_choice_namespace(routes, route_ordinal)
                }),
            )];
            let path = PartialPath::new(
                closed_endpoint(
                    identities.source_reference_node(reference.fact.reference),
                    Vec::new(),
                ),
                closed_endpoint(BindingNodeId::universal_root(), root_symbols),
                precedence,
                witness,
                completion_for_site(reasons_by_site, reference.fact.reference, |origin| {
                    index.lexical_reference_gap(reference.fact.reference, origin)
                }),
            );
            let path = if reference.fact.owner_continued {
                path.with_owner_continued()
            } else {
                path
            };
            paths.push((id, path));
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
                    identities.gap_reason(source.site, source.origin),
                ));
        }
    }
    scope_reasons
}

/// A missing binder has the same namespace aliases as an affirmative one.
/// Unknown namespaces include macros and constructors; known Scala callables
/// also bind in Value through the existing language hook.
fn binder_gap_namespaces(
    language: Language,
    namespace: Option<ResolutionNamespace>,
) -> impl Iterator<Item = ResolutionNamespace> {
    namespace
        .into_iter()
        .flat_map(|namespace| {
            lookup_routes(namespace)
                .iter()
                .map(|&(_, namespace)| namespace)
        })
        .chain(
            namespace
                .is_none()
                .then_some(EFFECTIVE_NAMESPACES)
                .into_iter()
                .flatten(),
        )
        .chain(
            (namespace == Some(ResolutionNamespace::Callable)
                && language_callables_occupy_value_namespace(language))
            .then_some(ResolutionNamespace::Value),
        )
}

/// Exact export and package bridges bypass lexical scope checkpoints. Carry
/// publishing binder uncertainty and exact export availability for this name.
fn route_publication_completion(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
    scope: ResolutionScopeId,
    name: ResolutionNameId,
    namespace: ResolutionNamespace,
) -> ResolutionCompletion {
    let mut reasons = index
        .publishing_route_gaps_by_scope
        .get(&scope)
        .into_iter()
        .flatten()
        .filter_map(|gap| {
            let ResolutionRouteGap::UnknownBinder {
                scope: binding_scope,
                name: binding_name,
                namespace: binding_namespace,
                may_publish: true,
            } = gap.route().expect("publishing index contains route gaps")
            else {
                unreachable!("publishing index contains only publishing binder gaps");
            };
            debug_assert_eq!(binding_scope, scope);
            (binding_name.is_none_or(|bound| bound == name)
                && binder_gap_namespaces(language, binding_namespace)
                    .any(|effective| effective == namespace))
            .then(|| {
                ResolutionIncompleteReason::UnsupportedSemantic(identities.gap_reason(
                    gap.site,
                    LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute),
                ))
            })
        })
        .collect::<Vec<_>>();
    reasons.extend(
        index
            .unproven_exports
            .get(&(scope, name, namespace))
            .into_iter()
            .flat_map(|export| export.gaps.iter())
            .map(|gap| {
                ResolutionIncompleteReason::UnsupportedSemantic(identities.gap_reason(
                    gap.site,
                    LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute),
                ))
            }),
    );
    if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    }
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
        let completion = completion.combine(&route_publication_completion(
            identities,
            language,
            index,
            index.site(export.declaration).scope,
            identifier.name,
            export.namespace,
        ));
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

#[derive(Default)]
struct UnprovenExportFacts<'facts> {
    gaps: Vec<&'facts ResolutionGapFact>,
    declarations: Vec<ResolutionSiteId>,
}

#[doc(hidden)]
pub struct FactIndex<'facts> {
    anonymous_callables: HashSet<ResolutionSiteId>,
    scope_continuations: HashMap<ResolutionScopeId, Option<ResolutionScopeId>>,
    names: HashMap<ResolutionNameId, &'facts str>,
    scopes: HashMap<ResolutionScopeId, ResolutionScopeFact>,
    sites: HashMap<ResolutionSiteId, ResolutionSiteFact>,
    #[doc(hidden)]
    pub identifiers_by_site: HashMap<ResolutionSiteId, Vec<&'facts PositionedIdentifierFact>>,
    additional_definition_namespaces_by_declaration:
        HashMap<ResolutionSiteId, Vec<ResolutionAdditionalDefinitionNamespaceFact>>,
    /// Callable declarations that a Value lookup also reaches
    /// (`language_callables_occupy_value_namespace`).
    value_aliased_callables: HashSet<ResolutionSiteId>,
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
    implicit_interface_member_references: HashSet<ResolutionSiteId>,
    type_body_scope_by_owner: HashMap<ResolutionSiteId, ResolutionScopeFact>,
    structured_import_by_site: HashMap<ResolutionSiteId, StructuredImportFact>,
    root_imports: Vec<IndexedRootImport>,
    root_references: Vec<IndexedRootReference>,
    root_exports: Vec<ResolutionRootExportFact>,
    // Both indexes belong to this immutable file's lowering and are dropped
    // with it. Repeated point/export reads must not rescan all ordinary gaps.
    route_gaps_by_site: HashMap<ResolutionSiteId, Vec<ResolutionRouteGap>>,
    publishing_route_gaps_by_scope: HashMap<ResolutionScopeId, Vec<&'facts ResolutionGapFact>>,
    // File-local exact export obligations and their validated declaration endpoints.
    unproven_exports: HashMap<
        (ResolutionScopeId, ResolutionNameId, ResolutionNamespace),
        UnprovenExportFacts<'facts>,
    >,
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
    /// The producer's named or wildcard classification, including legacy route
    /// metadata. See [`root_import_precedence`].
    kind: ResolutionRootImportKind,
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
            // A positioned reference may itself be a syntactic guess (for
            // example, an argument of a macro with no visible definition).
            // Its spelling is enumerable, but its binding is not proven.
            && (lexical_gap(origin)
                || origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpression))
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
                        | ResolutionScopeKind::TypeBody
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
                    kind: if facts.root_import_kinds.iter().any(|kind| {
                        kind.import_site == fact.site
                            && kind.kind == ResolutionRootImportKind::Named
                    }) || facts.import_routes.iter().any(|route| {
                        route.site == fact.site
                            && matches!(
                                route.kind,
                                ResolutionImportRouteKind::SingleType
                                    | ResolutionImportRouteKind::SingleStatic
                                    | ResolutionImportRouteKind::Named
                            )
                    }) {
                        ResolutionRootImportKind::Named
                    } else {
                        ResolutionRootImportKind::Glob
                    },
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
        prefix_rule: Option<RootPrefixRule>,
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
                    prefix_rule.is_some_and(|rule| {
                        rule.prefix_namespaces
                            .contains(&prefix_identifier.namespace)
                    }),
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

    #[doc(hidden)]
    pub fn new(language: Language, facts: &'facts FileResolutionFacts) -> Self {
        let mut unproven_exports: HashMap<_, UnprovenExportFacts<'_>> = HashMap::default();
        let mut route_gaps_by_site: HashMap<_, Vec<_>> = HashMap::default();
        let mut publishing_route_gaps_by_scope: HashMap<_, Vec<_>> = HashMap::default();
        for gap in &facts.gaps {
            assert_eq!(
                gap.kind == ResolutionGapKind::UnsupportedRoute,
                gap.route().is_some(),
                "only route gaps carry required classified coordinates"
            );
            if let Some(route) = gap.route() {
                if let ResolutionRouteGap::UnprovenExport {
                    scope,
                    name,
                    namespace,
                } = route
                {
                    unproven_exports
                        .entry((scope, name, namespace))
                        .or_default()
                        .gaps
                        .push(gap);
                }
                route_gaps_by_site
                    .entry(gap.site)
                    .or_default()
                    .push(route.clone());
                if let ResolutionRouteGap::UnknownBinder {
                    scope,
                    may_publish: true,
                    ..
                } = route
                {
                    publishing_route_gaps_by_scope
                        .entry(scope)
                        .or_default()
                        .push(gap);
                }
            }
        }

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
            // A type declaration occupies the Type namespace, or the Value
            // namespace when the producer declares it as a term that owns a
            // member scope (a Scala `object`).
            let declared_term_type = |site: ResolutionSiteId, namespace: ResolutionNamespace| {
                namespace == ResolutionNamespace::Value
                    && facts.additional_definition_namespaces.iter().any(|fact| {
                        fact.declaration == site && fact.namespace == ResolutionNamespace::Value
                    })
            };
            assert!(
                declaration.role == ResolutionIdentifierRole::Declaration
                    && (sites[&member.member].kind == member_kind
                        || (member.kind == ResolutionMemberKind::Field
                            && sites[&member.member].kind == ResolutionSiteKind::TypeDeclaration
                            && declared_term_type(member.member, declaration.namespace)))
                    && (declaration.namespace == member_namespace
                        || (member.kind == ResolutionMemberKind::NestedType
                            && declared_term_type(member.member, declaration.namespace))),
                "member-owner member shape is invalid: {member:?}, declaration={declaration:?}"
            );
            assert!(
                owner.role == ResolutionIdentifierRole::Declaration
                    && (matches!(
                        (sites[&member.owner].kind, owner.namespace),
                        (
                            ResolutionSiteKind::TypeDeclaration,
                            ResolutionNamespace::Type
                        ) | (
                            ResolutionSiteKind::ConstructorDeclaration,
                            ResolutionNamespace::Constructor
                        )
                    ) || (sites[&member.owner].kind == ResolutionSiteKind::TypeDeclaration
                        && declared_term_type(member.owner, owner.namespace))),
                "member-owner type shape is invalid: {member:?}, owner={owner:?}"
            );
            if member.kind == ResolutionMemberKind::Field {
                assert!(field_declarations.insert(member.member));
            }
        }
        let anonymous_callables =
            super::common_fact_lowering::anonymous_callable_declarations(facts, |site| {
                identifiers_by_site.contains_key(&site)
            });
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
                if let Some(declaration) = identifiers_by_site
                    .get(&owner)
                    .and_then(|identifiers| identifiers.first())
                {
                    assert_eq!(
                        declaration.role,
                        ResolutionIdentifierRole::Declaration,
                        "reference containment owner must be a positioned declaration: {enclosing:?}"
                    );
                } else {
                    // A declaration value also anchors an anonymous callable;
                    // it creates no invented identifier or lexical binder.
                    assert!(
                        anonymous_callables.contains(&owner),
                        "reference containment names unknown declaration site {owner}"
                    );
                    assert_eq!(sites[&owner].kind, ResolutionSiteKind::CallableDeclaration);
                }
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
            assert!(
                receiver.origin.is_reference_valid(
                    reference.namespace,
                    sites[&receiver.reference].kind,
                    reference.qualifier.is_none(),
                ),
                "receiver origin must name a callable or field reference with matching qualification: {receiver:?}, {reference:?}"
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
            assert_ne!(
                additional.namespace,
                ResolutionNamespace::TypeOrValue,
                "additional definition namespace must be effective: {additional:?}"
            );
            let identifier = identifiers_by_site
                .get(&additional.declaration)
                .and_then(|identifiers| identifiers.first());
            if let Some(identifier) = identifier {
                assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
            }
            let hoisting = if facts
                .route_owned_module_declarations
                .contains(&additional.declaration)
            {
                assert_eq!(
                    sites[&additional.declaration].kind,
                    ResolutionSiteKind::ModuleDeclaration
                );
                if let Some(identifier) = identifier {
                    assert_eq!(identifier.namespace, additional.namespace);
                }
                HoistingClass::ScopeWide
            } else {
                assert!(
                    identifier.is_some(),
                    "a named binder needs an identifier: {additional:?}"
                );
                facts.binders.iter()
                    .find(|binder| binder.declaration == additional.declaration)
                    .unwrap_or_else(|| panic!(
                        "additional definition namespace names declaration without a binder: {additional:?}"
                    )).hoisting
            };
            assert_eq!(
                additional.hoisting, hoisting,
                "definition namespace authority must declare its activation: {additional:?}"
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
        // A producer that already files a callable under Value keeps its own
        // fact; every other callable of a term-namespace language is aliased.
        let mut value_aliased_callables = HashSet::default();
        if language_callables_occupy_value_namespace(language) {
            for binder in &facts.binders {
                let identifier = identifiers_by_site
                    .get(&binder.declaration)
                    .and_then(|identifiers| identifiers.first())
                    .unwrap_or_else(|| {
                        panic!("binder names declaration without an identifier: {binder:?}")
                    });
                if identifier.namespace == ResolutionNamespace::Callable
                    && !additional_definition_namespaces_by_declaration
                        .get(&binder.declaration)
                        .is_some_and(|namespaces| {
                            namespaces
                                .iter()
                                .any(|fact| fact.namespace == ResolutionNamespace::Value)
                        })
                {
                    value_aliased_callables.insert(binder.declaration);
                }
            }
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
        let implicit_interface_member_references = facts.supertypes.iter()
            .filter(|edge| edge.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind::ImplicitInterfaceMembers)
            .map(|edge| edge.supertype_reference)
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
                ResolutionImportRouteKind::SingleType
                | ResolutionImportRouteKind::SingleStatic
                | ResolutionImportRouteKind::Named => {
                    assert!(
                        route
                            .bound_name
                            .is_some_and(|name| names.contains_key(&name))
                    );
                }
                ResolutionImportRouteKind::TypeOnDemand
                | ResolutionImportRouteKind::StaticOnDemand
                | ResolutionImportRouteKind::Star => {
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

        let root_references = Self::index_root_references(
            root_prefix_rule(language),
            facts,
            &names,
            &scopes,
            &sites,
            &identifiers_by_site,
        );
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
        for export in &root_exports {
            let identifier = identifiers_by_site[&export.declaration][0];
            if let Some(availability) =
                unproven_exports.get_mut(&(export.root_scope, identifier.name, export.namespace))
            {
                availability.declarations.push(export.declaration);
            }
        }
        for (coordinates, availability) in &unproven_exports {
            assert!(
                !availability.declarations.is_empty(),
                "unproven export must name a published export: {coordinates:?}"
            );
        }
        root_exports.sort_unstable_by_key(|export| {
            (export.root_scope, export.declaration, export.namespace)
        });
        let mut scope_continuations = HashMap::default();
        for continuation in &facts.scope_continuations {
            assert!(
                scope_continuations
                    .insert(continuation.scope, continuation.parent)
                    .is_none(),
                "duplicate scope continuation: {continuation:?}"
            );
        }
        Self {
            scope_continuations,
            route_gaps_by_site,
            publishing_route_gaps_by_scope,
            unproven_exports,
            names,
            scopes,
            sites,
            identifiers_by_site,
            additional_definition_namespaces_by_declaration,
            value_aliased_callables,
            reference_owner_by_reference,
            anonymous_callables,
            callable_receiver_origin_by_reference,
            argument_independent_references: Self::index_argument_independent_references(facts),
            keyword_references: facts.keyword_references.iter().copied().collect(),
            type_slots_by_site,
            supertype_owner_by_reference,
            implicit_superclass_references,
            implicit_interface_member_references,
            type_body_scope_by_owner,
            structured_import_by_site,
            root_imports,
            root_references,
            root_exports,
        }
    }

    fn validate_scope_forest(&self) {
        super::common_fact_lowering::validate_scope_forest(&self.scopes);
        super::common_fact_lowering::validate_scope_continuations(
            &self.scopes,
            &self.scope_continuations,
        );
    }

    fn lookup_scope_parent(&self, scope: ResolutionScopeId) -> Option<ResolutionScopeId> {
        super::common_fact_lowering::lookup_scope_parent(
            self.scope(scope),
            &self.scope_continuations,
        )
    }

    #[doc(hidden)]
    pub fn name(&self, id: ResolutionNameId) -> &str {
        required_resolution_name(&self.names, id)
    }

    fn scope(&self, id: ResolutionScopeId) -> ResolutionScopeFact {
        required_resolution_scope(&self.scopes, id)
    }

    fn site(&self, id: ResolutionSiteId) -> ResolutionSiteFact {
        super::required_resolution_site(&self.sites, id)
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
        super::common_fact_lowering::assert_declaration_identifier(identifier);
        identifier
    }

    fn reference_identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        let identifier = self.identifier(site);
        super::assert_reference_identifier(identifier);
        identifier
    }

    fn reference_identifier_if_present(
        &self,
        site: ResolutionSiteId,
    ) -> Option<&'facts PositionedIdentifierFact> {
        self.identifiers_by_site
            .get(&site)?
            .iter()
            .copied()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
    }

    // Root routes suppress lexical lookup unless the producer explicitly
    // publishes a lexical import-qualifier role. Metadata and route publication
    // must agree so enclosing-template members remain visible to that head.
    fn suppresses_lexical_lookup(&self, site: ResolutionSiteId) -> bool {
        self.root_reference(site).is_some()
            && self.site(site).kind != ResolutionSiteKind::ImportQualifierReference
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

    fn receiver_origin(&self, site: ResolutionSiteId) -> Option<ResolutionCallableReceiverOrigin> {
        self.callable_receiver_origin_by_reference
            .get(&site)
            .copied()
    }

    fn identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        super::required_positioned_identifier(
            self.identifiers_by_site
                .get(&site)
                .and_then(|identifiers| identifiers.first())
                .copied(),
            site,
        )
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

/// What a language lets a root reference continue from.
#[derive(Debug, Clone, Copy)]
struct RootPrefixRule {
    /// The namespaces its positioned prefix reference may have. A Type prefix
    /// guards the package reading against lexical shadowing; a type-or-value
    /// prefix may be a package, a type object or a value.
    prefix_namespaces: &'static [ResolutionNamespace],
    /// Whether the terminal of a prefixed root reference may keep the
    /// grammar-ambiguous type-or-value namespace, which lowers one route in
    /// each namespace.
    terminal_namespace: Option<ResolutionNamespace>,
    /// The selected prefix already consumed the first authored route segment.
    consume_prefix_segment: bool,
    /// Namespace of the remaining container route.
    route_namespace: ResolutionNamespace,
    /// Absolute and lexical roots may retain ambiguity without a prefix.
    unprefixed_type_or_value: bool,
    /// Whether a prefixed route is exactly one positioned qualifier.
    single_prefix_segment: bool,
}

/// The prefix rule of a language, or `None` when it publishes no positioned
/// root prefixes. Rust and Java keep the Type prefix. Go classifies a package
/// or value qualifier. Scala and Kotlin name terms through packages, objects and
/// values, so their prefix may be either; Kotlin has only the rule so far.
const fn root_prefix_rule(language: Language) -> Option<RootPrefixRule> {
    const TYPE: &[ResolutionNamespace] = &[ResolutionNamespace::Type];
    const TYPE_OR_VALUE: &[ResolutionNamespace] = &[ResolutionNamespace::TypeOrValue];
    const BOTH: &[ResolutionNamespace] =
        &[ResolutionNamespace::Type, ResolutionNamespace::TypeOrValue];
    match language {
        Language::Rust => Some(RootPrefixRule {
            prefix_namespaces: TYPE,
            terminal_namespace: None,
            consume_prefix_segment: true,
            route_namespace: ResolutionNamespace::Type,
            unprefixed_type_or_value: false,
            single_prefix_segment: false,
        }),
        Language::Java => Some(RootPrefixRule {
            prefix_namespaces: TYPE,
            terminal_namespace: None,
            consume_prefix_segment: false,
            route_namespace: ResolutionNamespace::Type,
            unprefixed_type_or_value: false,
            single_prefix_segment: false,
        }),
        // ECMA-334 12.8.4: an ambiguous name can denote a namespace, type or value.
        Language::CSharp => Some(RootPrefixRule {
            prefix_namespaces: BOTH,
            terminal_namespace: Some(ResolutionNamespace::TypeOrValue),
            consume_prefix_segment: false,
            route_namespace: ResolutionNamespace::Type,
            unprefixed_type_or_value: true,
            single_prefix_segment: false,
        }),
        Language::Go => Some(RootPrefixRule {
            prefix_namespaces: TYPE_OR_VALUE,
            terminal_namespace: Some(ResolutionNamespace::TypeOrValue),
            consume_prefix_segment: true,
            route_namespace: ResolutionNamespace::Type,
            unprefixed_type_or_value: false,
            single_prefix_segment: true,
        }),
        Language::Python => Some(RootPrefixRule {
            prefix_namespaces: &[ResolutionNamespace::Value],
            terminal_namespace: Some(ResolutionNamespace::Value),
            consume_prefix_segment: true,
            route_namespace: ResolutionNamespace::Value,
            unprefixed_type_or_value: false,
            single_prefix_segment: true,
        }),
        Language::Kotlin | Language::Scala => Some(RootPrefixRule {
            prefix_namespaces: BOTH,
            terminal_namespace: Some(ResolutionNamespace::TypeOrValue),
            consume_prefix_segment: false,
            route_namespace: ResolutionNamespace::Type,
            unprefixed_type_or_value: matches!(language, Language::Scala),
            single_prefix_segment: false,
        }),
        _ => None,
    }
}

#[doc(hidden)]
pub fn lookup_routes(namespace: ResolutionNamespace) -> &'static [(u32, ResolutionNamespace)] {
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

/// The lookups an unqualified lexical reference makes. A callee in a language
/// whose types can be called also searches the Type namespace: the lookup that
/// lands on a type is interpreted by `type_in_call_position` when the call is
/// resolved.
#[doc(hidden)]
pub fn lexical_lookup_routes(
    language: Language,
    namespace: ResolutionNamespace,
) -> &'static [(u32, ResolutionNamespace)] {
    if namespace == ResolutionNamespace::Callable
        && super::fact_resolution::type_in_call_position(language)
            == super::fact_resolution::TypeInCallPosition::Constructors
    {
        &[
            (0, ResolutionNamespace::Callable),
            (1, ResolutionNamespace::Type),
        ]
    } else {
        lookup_routes(namespace)
    }
}

pub(super) fn call_target_lookup_routes(
    language: Language,
    is_call_target: bool,
) -> Option<&'static [(u32, ResolutionNamespace)]> {
    is_call_target.then_some(())?;
    crate::analyzer::semantic::languages::language_knowledge(language)?.call_target_lookup_routes()
}

/// Namespace authority for a ranked family, shared by all of its routes.
/// Scala's Callable and Value routes select the same term namespace.
fn call_target_choice_namespace(
    routes: &[(u32, ResolutionNamespace)],
    rank: u32,
) -> ResolutionNamespace {
    routes
        .iter()
        .filter(|(candidate_rank, _)| *candidate_rank == rank)
        .map(|(_, namespace)| *namespace)
        .min()
        .expect("an emitted callee rank has a namespace authority")
}

fn single_import_namespaces(kind: ResolutionImportRouteKind) -> &'static [ResolutionNamespace] {
    match kind {
        ResolutionImportRouteKind::SingleType => &[ResolutionNamespace::Type],
        ResolutionImportRouteKind::SingleStatic => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        ResolutionImportRouteKind::Named => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        ResolutionImportRouteKind::TypeOnDemand
        | ResolutionImportRouteKind::StaticOnDemand
        | ResolutionImportRouteKind::Star => &[],
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

#[doc(hidden)]
pub fn go_spelling_choice_identity(
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
    scope_fallback_precedence_for_namespaces(identities, scope, &EFFECTIVE_NAMESPACES)
}

fn scope_fallback_precedence_for_namespaces(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
    namespaces: &[ResolutionNamespace],
) -> Vec<PrecedenceStep> {
    namespaces
        .iter()
        .map(|&namespace| {
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
    type_body_precedence(identities, scope, 1)
}

fn type_body_hierarchy_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    type_body_precedence(identities, scope, 0)
}

fn type_body_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
    hierarchy_ordinal: u32,
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
                registered_precedence_step(identities, hierarchy, hierarchy_ordinal, namespace),
            ]
        })
        .collect()
}

fn binder_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    timeline: &ScopeTimeline,
    binder: &SupportedBinder<'_>,
    namespace: ResolutionNamespace,
) -> Vec<PrecedenceStep> {
    let direct_choice = match binder.activation {
        SupportedActivation::ScopeWide => {
            identities.semantic(scope_choice_identity(timeline.fact.id, namespace))
        }
        SupportedActivation::SourceOrder(position)
        | SupportedActivation::DeclaredHead {
            start: position, ..
        } => identities.semantic(checkpoint_choice_identity(
            timeline.fact.id,
            position,
            namespace,
        )),
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
    let mut precedence = if timeline.fact.kind == ResolutionScopeKind::TypeBody
        && (binder.fact.kind == ResolutionBinderKind::Callable
            || (matches!(binder.fact.kind, ResolutionBinderKind::Alias { .. })
                && binder.identifier.namespace == ResolutionNamespace::Callable))
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
    } else if timeline.fact.kind == ResolutionScopeKind::CompilationUnit
        && language_explicit_imports_outrank_package_binders(language)
    {
        // The package's own declarations rank with other package members, so
        // an explicit import on the same choice shadows them.
        vec![identities.register_precedence_namespace(
            PrecedenceStep {
                tier: PrecedenceTier::PackageOrModule,
                ordinal: 0,
                semantic: direct_choice,
            },
            namespace,
        )]
    } else {
        vec![registered_precedence_step(
            identities,
            direct_choice,
            0,
            namespace,
        )]
    };
    if let Some(origin) = language_lexical_binder_origin(language)
        && let Some(ordinal) = binding_origin_rank(language, origin)
    {
        precedence.push(identities.register_precedence_namespace(
            PrecedenceStep {
                tier: PrecedenceTier::CandidateOriginRank,
                ordinal,
                semantic: direct_choice,
            },
            namespace,
        ));
    }
    precedence
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

/// Result slots whose declared types do not depend on invocation validity.
/// This set belongs to one immutable file's lowering and is never retained.
pub(super) fn applicability_independent_result_slots(
    language: Language,
    facts: &FileResolutionFacts,
) -> HashSet<ResolutionTypeSlotId> {
    if !crate::analyzer::semantic::languages::language_knowledge(language)
        .is_some_and(|support| support.callable_result_is_applicability_independent())
    {
        return HashSet::default();
    }
    facts
        .callable_signatures
        .iter()
        .flat_map(|signature| {
            signature
                .result_types
                .iter()
                .map(|result| result.value_type)
        })
        .collect()
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

/// The namespaces in which a package of `language` holds members, for the
/// languages whose producers publish source-owned package lookups. A reference
/// in another namespace never consults the package inventory, so the unknown
/// placement of the file cannot hide a package member from it. An empty list
/// means the language publishes no package lookups, so they cannot cover its
/// placement.
const fn package_member_namespaces(language: Language) -> &'static [ResolutionNamespace] {
    match language {
        Language::Kotlin | Language::Scala => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
            ResolutionNamespace::TypeOrValue,
        ],
        // A Java package holds only types: fields and methods belong to a
        // class, and a static import names a class member.
        // ECMA-334 14.7: namespaces contain namespace and type declarations.
        Language::CSharp | Language::Java => {
            &[ResolutionNamespace::Type, ResolutionNamespace::TypeOrValue]
        }
        Language::Go
        | Language::Rust
        | Language::Cpp
        | Language::JavaScript
        | Language::TypeScript
        | Language::Python
        | Language::Php
        | Language::Ruby
        | Language::None => &[],
    }
}

fn package_lookups_cover_placement(
    language: Language,
    facts: &FileResolutionFacts,
    index: &FactIndex<'_>,
    placement_site: ResolutionSiteId,
    root_scope: ResolutionScopeId,
) -> bool {
    let package_namespaces = package_member_namespaces(language);
    if package_namespaces.is_empty()
        || !facts.packages.iter().any(|package| {
            package.placement_gap_site == placement_site && package.root_scope == root_scope
        })
    {
        return false;
    }
    let package_references = facts
        .package_references
        .iter()
        .filter(|reference| reference.root_scope == root_scope)
        .map(|reference| reference.reference)
        .collect::<HashSet<_>>();
    let rooted_references = facts
        .root_references
        .iter()
        .map(|reference| reference.reference)
        .collect::<HashSet<_>>();
    let imported_names = facts
        .import_routes
        .iter()
        .filter_map(|route| route.bound_name)
        .collect::<HashSet<_>>();
    for identifier in &facts.identifiers {
        if identifier.role != ResolutionIdentifierRole::Reference {
            continue;
        }
        let mut scope = index.site(identifier.site).scope;
        while scope != root_scope {
            let Some(parent) = index.scope(scope).parent else {
                break;
            };
            scope = parent;
        }
        if scope != root_scope || identifier.qualifier.is_some() {
            continue;
        }
        if identifier.namespace == ResolutionNamespace::Package {
            // A package path segment of an import is resolved by the import's
            // root route, never by a lookup among the package's members, so
            // it neither needs coverage nor leaves any open.
            continue;
        }
        if !matches!(
            identifier.namespace,
            ResolutionNamespace::Type
                | ResolutionNamespace::Value
                | ResolutionNamespace::Callable
                | ResolutionNamespace::TypeOrValue
        ) {
            return false;
        }
        if !package_namespaces.contains(&identifier.namespace)
            || rooted_references.contains(&identifier.site)
            || imported_names.contains(&identifier.name)
        {
            continue;
        }
        if !package_references.contains(&identifier.site) {
            return false;
        }
    }
    true
}

fn gap_reasons_by_site(
    identities: &mut ResolutionIdentityCatalogBuilder,
    sources: &[GapSource],
) -> HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>> {
    let mut reasons: HashMap<_, Vec<_>> = HashMap::default();
    for source in sources {
        reasons.entry(source.site).or_default().push((
            source.origin,
            identities.gap_reason(source.site, source.origin),
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
    facts: &'source FileResolutionFacts,
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
        let reason_semantic =
            identities.gap_reason(import.fact.site, LoweringGapOrigin::ExternalPreludeBoundary);
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

/// Binary owners are supplied by producers. These fixed-width endpoint keys
/// never encode or infer a language's binary naming conventions.
pub(crate) fn alias_surface_node_identity<'a>(
    owner: impl IntoIterator<Item = &'a str>,
    namespace: ResolutionNamespace,
) -> ResolutionNodeIdentity {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-alias-owner-surface:v1");
    hash.field("namespace", namespace.identity_label().as_bytes());
    for segment in owner {
        hash.field("segment", segment.as_bytes());
    }
    ResolutionNodeIdentity::new(hash.finish())
}

pub(crate) fn alias_prefix_surface_node_identity<'a>(
    prefix: impl IntoIterator<Item = &'a str>,
    namespace: ResolutionNamespace,
) -> ResolutionNodeIdentity {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-alias-owner-prefix-surface:v1");
    hash.field("namespace", namespace.identity_label().as_bytes());
    for segment in prefix {
        hash.field("segment", segment.as_bytes());
    }
    ResolutionNodeIdentity::new(hash.finish())
}

#[doc(hidden)]
pub fn alias_lookup_surface_node_identities(
    owner: &[impl AsRef<str>],
    namespace: ResolutionNamespace,
) -> Vec<ResolutionNodeIdentity> {
    let mut identities = Vec::with_capacity(owner.len() + 2);
    identities.push(alias_surface_node_identity(
        owner.iter().map(AsRef::as_ref),
        namespace,
    ));
    identities.extend((0..=owner.len()).map(|length| {
        alias_prefix_surface_node_identity(owner[..length].iter().map(AsRef::as_ref), namespace)
    }));
    identities
}

fn alias_gap_namespaces(
    kind: Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasKind>,
) -> &'static [ResolutionNamespace] {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasKind;
    match kind {
        Some(
            ResolutionJvmAliasKind::Field
            | ResolutionJvmAliasKind::CompanionObject
            | ResolutionJvmAliasKind::SingletonInstance,
        ) => &[ResolutionNamespace::Value],
        Some(ResolutionJvmAliasKind::Constructor) => &[ResolutionNamespace::Constructor],
        Some(_) => &[ResolutionNamespace::Callable],
        None => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
            ResolutionNamespace::Constructor,
        ],
    }
}

fn alias_route_surface_node_identity(
    route: &ResolutionBinaryOwnerRoute,
    index: &FactIndex<'_>,
    namespace: ResolutionNamespace,
) -> ResolutionNodeIdentity {
    // Every class-d fact must carry a binary route, including access-only
    // provenance. Validate it here before constructing any coverage frontier.
    match route {
        ResolutionBinaryOwnerRoute::Exact(segments) => {
            assert!(
                !segments.is_empty(),
                "an exact JVM binary owner needs a name"
            );
            alias_surface_node_identity(segments.iter().map(|&name| index.name(name)), namespace)
        }
        ResolutionBinaryOwnerRoute::UnknownWithin { scope, prefix } => {
            index.scope(*scope);
            alias_prefix_surface_node_identity(
                prefix.iter().map(|&name| index.name(name)),
                namespace,
            )
        }
    }
}

fn classified_route_frontiers(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    route: ResolutionRouteGap,
    index: &FactIndex<'_>,
    semantics: &HashMap<(ResolutionSiteId, LoweredSemanticRole), (SemanticId, BindingNodeId)>,
    forward_gap_endpoints: &HashMap<ResolutionSiteId, Vec<BindingNodeId>>,
) -> Vec<LoweringCoverageFrontier> {
    let mut frontiers = Vec::new();
    let namespaces = EFFECTIVE_NAMESPACES;
    match route {
        ResolutionRouteGap::OmittedReference {
            scope,
            terminal,
            namespace,
        } => {
            if let Some(terminal) = terminal {
                for &namespace in namespace
                    .as_ref()
                    .map(std::slice::from_ref)
                    .unwrap_or(&namespaces)
                {
                    for &(_, namespace) in lookup_routes(namespace) {
                        let lookup =
                            identities.lookup_semantic(language, namespace, index.name(terminal));
                        for endpoint in [
                            identities.source_scope_node(scope),
                            BindingNodeId::universal_root(),
                        ] {
                            frontiers.push(LoweringCoverageFrontier::Candidate {
                                direction: LoweredCandidateDirection::Reverse,
                                endpoint,
                                lookup: Some(lookup),
                            });
                        }
                    }
                }
            } else {
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
        }
        ResolutionRouteGap::UnprovenExport {
            scope,
            name,
            namespace,
        } => {
            for &declaration in &index.unproven_exports[&(scope, name, namespace)].declarations {
                let &(_, endpoint) = semantics
                    .get(&(declaration, LoweredSemanticRole::Definition))
                    .expect("published export has a definition endpoint");
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Reverse,
                    endpoint,
                    lookup: None,
                });
            }
        }
        ResolutionRouteGap::UnknownBinder {
            scope,
            name,
            namespace,
            may_publish,
        } => {
            let mut endpoints = vec![identities.source_scope_node(scope)];
            if may_publish
                && let Some(owner) = index.scope(scope).owner
                && let Some(&(_, definition)) =
                    semantics.get(&(owner, LoweredSemanticRole::Definition))
            {
                endpoints.push(definition);
            }
            for endpoint in endpoints {
                if let Some(name) = name {
                    for namespace in binder_gap_namespaces(language, namespace) {
                        frontiers.push(LoweringCoverageFrontier::Candidate {
                            direction: LoweredCandidateDirection::Forward,
                            endpoint,
                            lookup: Some(identities.lookup_semantic(
                                language,
                                namespace,
                                index.name(name),
                            )),
                        });
                    }
                } else {
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Forward,
                        endpoint,
                        lookup: None,
                    });
                }
            }
            // Exact export bridges may bypass lexical scope checkpoints.
            if may_publish {
                for (&(site, role), &(_, endpoint)) in semantics {
                    if role == LoweredSemanticRole::Definition && index.site(site).scope == scope {
                        frontiers.push(LoweringCoverageFrontier::Candidate {
                            direction: LoweredCandidateDirection::Reverse,
                            endpoint,
                            lookup: None,
                        });
                    }
                }
            }
        }
        ResolutionRouteGap::UnknownPlacement => {
            assert_eq!(
                route,
                ResolutionRouteGap::UnknownPlacement,
                "only unknown package placement may create Fragment coverage"
            );
            // #5658: milestone 2b slice 7's JVM containers and placements
            // replace this with Unplaced admission. Delete Fragment and its
            // readers once that admission preserves the local evidence.
            frontiers.push(LoweringCoverageFrontier::Fragment);
            frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            });
        }
        ResolutionRouteGap::UnknownAlias {
            owner,
            binary_owner,
            name,
            kind,
        } => {
            // Required even on access-only facts; validate before constructing
            // either a source-access or a binary-alias frontier.
            alias_route_surface_node_identity(&binary_owner, index, ResolutionNamespace::Callable);
            if let ResolutionRouteOwner::DeclarationAccess(owner) = owner {
                // The source binder is exact; only using this declaration's
                // access contract remains open. Keep its own binder-path
                // evidence and owner surface, never its whole lexical scope.
                let endpoint = identities.source_definition_node(owner);
                let identifier = index.declaration_identifier(owner);
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint,
                    lookup: None,
                });
                // Reuse the actual binder/member checkpoints, including
                // deferred member routes, rather than widening the scope.
                for &endpoint in forward_gap_endpoints.get(&owner).into_iter().flatten() {
                    for namespace in binder_gap_namespaces(language, Some(identifier.namespace)) {
                        frontiers.push(LoweringCoverageFrontier::Candidate {
                            direction: LoweredCandidateDirection::Forward,
                            endpoint,
                            lookup: Some(identities.lookup_semantic(
                                language,
                                namespace,
                                index.name(identifier.name),
                            )),
                        });
                    }
                }
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Reverse,
                    endpoint,
                    lookup: None,
                });
                return frontiers;
            }
            // A wildcard member name still has the known alias namespace.
            // Distinct endpoints prevent a missing getter/method from opening
            // a proven type identity on the same binary owner.
            for &namespace in alias_gap_namespaces(kind) {
                let endpoint = identities.node(alias_route_surface_node_identity(
                    &binary_owner,
                    index,
                    namespace,
                ));
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint,
                    lookup: name.map(|name| {
                        identities.lookup_semantic(Language::Java, namespace, index.name(name))
                    }),
                });
            }
        }
    }
    frontiers
}

fn lower_coverage_gaps(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    sources: GapCoverageSources<'_>,
    index: &FactIndex<'_>,
    semantics: &HashMap<(ResolutionSiteId, LoweredSemanticRole), (SemanticId, BindingNodeId)>,
    forward_gap_endpoints: &HashMap<ResolutionSiteId, Vec<BindingNodeId>>,
) -> Vec<LoweredCoverageGap> {
    let mut output = Vec::new();
    let independent_results = applicability_independent_result_slots(language, facts);
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
        let reason_semantic = identities.gap_reason(source.site, source.origin);
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
        if source.origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute) {
            let routes = index
                .route_gaps_by_site
                .get(&source.site)
                .expect("point route gap has classified producer facts");
            let mut frontiers = Vec::new();
            for route in routes {
                // Exact import routes carry destination obligations on
                // ranked paths. Only genuinely unknown binders open a scope.
                if matches!(
                    route,
                    ResolutionRouteGap::UnknownBinder {
                        may_publish: false,
                        ..
                    }
                ) && let Some(import) = index.structured_import(source.site)
                {
                    let namespaces = if import.bound_name.is_some() {
                        single_import_namespaces(import.kind)
                            .iter()
                            .copied()
                            .collect::<HashSet<_>>()
                    } else {
                        index
                            .root_imports
                            .iter()
                            .filter(|root| root.fact.site == source.site)
                            .flat_map(|root| root.demands.iter().map(|demand| demand.namespace))
                            .collect::<HashSet<_>>()
                    };
                    for namespace in namespaces {
                        frontiers.push(LoweringCoverageFrontier::Candidate {
                            direction: LoweredCandidateDirection::Forward,
                            endpoint: identities.node(structured_import_gap_sink_node_identity(
                                source.site,
                                namespace,
                            )),
                            lookup: None,
                        });
                    }
                } else {
                    frontiers.extend(classified_route_frontiers(
                        identities,
                        language,
                        route.clone(),
                        index,
                        semantics,
                        forward_gap_endpoints,
                    ));
                }
                if sources.enumeration.contains(&source)
                    || matches!(
                        route,
                        ResolutionRouteGap::OmittedReference { .. }
                            | ResolutionRouteGap::UnknownPlacement
                    )
                {
                    frontiers.push(LoweringCoverageFrontier::Enumeration);
                }
                if sources.enumeration.contains(&source)
                    && matches!(route, ResolutionRouteGap::UnknownBinder { .. })
                {
                    frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    });
                }
                if let Some(slots) = index.type_slots_by_site.get(&source.site)
                    && !matches!(route, ResolutionRouteGap::UnknownAlias { .. })
                {
                    for &slot in slots {
                        frontiers.push(LoweringCoverageFrontier::Type {
                            frontier: identities.semantic(type_slot_semantic_identity(slot)),
                        });
                    }
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
        if source.origin == LoweringGapOrigin::Extracted(ResolutionGapKind::GeneratedItemSurface)
            && crate::analyzer::semantic::languages::language_knowledge(language)
                .is_some_and(|support| support.generated_items_cannot_shadow_bindings())
        {
            // Expansion may add a new name in this lexical scope. Carry the
            // reason through lookup; shared binding refinement discharges it
            // after finding an existing binding, while absence stays open.
            frontiers.push(LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Forward,
                endpoint: identities.source_scope_node(index.site(source.site).scope),
                lookup: None,
            });
            // Attribute/derive bodies are authored. A function-like macro's
            // separate enumeration obligation below keeps its unknown
            // expansion's reverse inventory open (#5375).
        } else if matches!(
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
        }
        if sources.enumeration.contains(&source) {
            frontiers.push(LoweringCoverageFrontier::Enumeration);
            if sources.point.contains(&source)
                && source.origin != LoweringGapOrigin::QualifiedReference
            {
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
        }
        if source.origin == LoweringGapOrigin::QualifiedReference {
            if let Some(identifier) = index.reference_identifier_if_present(source.site) {
                // The member's spelling is an exact source fact even though
                // its receiver type is unresolved. Keep reverse uncertainty
                // at the universal endpoint for each namespace this
                // reference can name; unrelated terminal names remain
                // complete.
                for &(_, namespace) in lookup_routes(identifier.namespace) {
                    let lookup = identities.lookup_semantic(
                        language,
                        namespace,
                        index.name(identifier.name),
                    );
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint: identities.source_scope_node(index.site(source.site).scope),
                        lookup: Some(lookup),
                    });
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint: BindingNodeId::universal_root(),
                        lookup: Some(lookup),
                    });
                }
            } else {
                // If the producer cannot name the member, retain reverse
                // uncertainty for every lookup. This computed-terminal case
                // remains visible as a fragment-wide qualified-reference
                // gap in the gap census.
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
        }
        if hierarchy_boundary_gap(source.origin) && index.hierarchy_gap_owner(source.site).is_some()
        {
            // Declaration-owned hierarchy branches need typed reverse paths.
            // A type-only frontier (such as abstract Self) has no lexical
            // hierarchy branch; its own completion remains on the typed
            // consumer instead.
            frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            });
        }
        if source.origin
            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
        {
            let scope = placement_scope(index, source);
            if language == Language::Go {
                // An unplaced Go file can add references to package members,
                // but only under the names those source-owned members declare.
                // Keep each reverse branch at its package endpoint and at the
                // universal endpoint, keyed by that member's lookup identity.
                // The local branch handles single-file package scopes; the
                // boundary branch carries the same name across selected files.
                for member in facts.package_members.iter().filter(|member| {
                    let member_scope = index.scope(member.root_scope);
                    member_scope.kind == ResolutionScopeKind::Package
                        && member_scope.parent == Some(scope.id)
                }) {
                    let identifier = index.declaration_identifier(member.declaration);
                    let lookup = identities.lookup_semantic(
                        language,
                        member.namespace,
                        index.name(identifier.name),
                    );
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint: identities.source_scope_node(member.root_scope),
                        lookup: Some(lookup),
                    });
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint: BindingNodeId::universal_root(),
                        lookup: Some(lookup),
                    });
                }
            } else if !package_lookups_cover_placement(
                language,
                sources.facts,
                index,
                source.site,
                scope.id,
            ) {
                // Other producers still use this gap for placement boundaries
                // whose name inventory is not source-owned.
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
        }

        if let Some(&(semantic, node)) =
            semantics.get(&(source.site, LoweredSemanticRole::Reference))
            && lexical_gap(source.origin)
            && (language != Language::Go || index.lexical_reference_gap(source.site, source.origin))
        {
            // Go invocation-only gaps for an argument-independent call remain
            // on its typed obligation. They do not make the source binding
            // or reverse-reference inventory incomplete. Other producers keep
            // their established lexical coverage behavior.
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
            if !index.anonymous_callables.contains(&source.site)
                && (!sources.deferred_members.contains(&source.site)
                    || forward_gap_endpoints.contains_key(&source.site))
            {
                let identifier = index.declaration_identifier(source.site);
                let lookup = identities.lookup_semantic(
                    language,
                    effective_declaration_namespace(identifier.namespace),
                    index.name(identifier.name),
                );
                let forward_endpoints = forward_gap_endpoints
                    .get(&source.site)
                    .expect("lexical definition gap has a supported or withheld binder frontier");
                for &endpoint in forward_endpoints {
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Forward,
                        endpoint,
                        lookup: Some(lookup),
                    });
                }
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
                    if source.origin
                        == LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedCallApplicability,
                        )
                        && independent_results.contains(&slot)
                    {
                        continue;
                    }
                    frontiers.push(LoweringCoverageFrontier::Type {
                        frontier: identities.semantic(type_slot_semantic_identity(slot)),
                    });
                }
            }
            if frontiers.is_empty() {
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

        if frontiers.is_empty() && language == Language::Rust {
            // Every structured reverse candidate needs a persisted reason row.
            // Semantic-only Rust gaps otherwise disappear here because they do
            // not open the type, lexical, or enumeration frontiers above.
            frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            });
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

fn open_endpoint(node: BindingNodeId, variable: StackVariableId) -> EndpointSignature {
    super::open_endpoint(node, Vec::new(), variable)
}

#[doc(hidden)]
pub fn symbol_open_endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
    variable: StackVariableId,
) -> EndpointSignature {
    super::open_endpoint(node, symbols, variable)
}

fn local_digest(domain: &[u8], fields: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    for &(name, value) in fields {
        hasher.field(name, value);
    }
    hasher.finish()
}

pub(super) fn site_identity_digest(domain: &[u8], field: &str, site: ResolutionSiteId) -> [u8; 32] {
    local_digest(domain, &[(field, &u32_bytes(site.get()))])
}

fn site_namespace_digest(
    domain: &[u8],
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> [u8; 32] {
    local_digest(
        domain,
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    )
}

fn scope_identity_digest(domain: &[u8], field: &str, scope: ResolutionScopeId) -> [u8; 32] {
    local_digest(domain, &[(field, &u32_bytes(scope.get()))])
}

fn scope_namespace_digest(
    domain: &[u8],
    scope_field: &str,
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> [u8; 32] {
    local_digest(
        domain,
        &[
            (scope_field, &u32_bytes(scope.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    )
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

/// Whether one JVM receiver-prefix gap is local to the exact type name being
/// projected. Placement boundaries belong to that compilation unit; implicit
/// receiver gaps belong to the exact reference site that could name a value.
/// A language whose lexical type outranks a package of the same name also
/// retires the prefix site's own ambiguity: once the prefix binds a type, the
/// qualified name cannot be a package path.
pub(crate) fn jvm_type_prefix_gap_origin_is_safe(
    language: Language,
    fragment: BindingFragmentId,
    source_site: ResolutionSiteId,
    origin: LoweringGapOrigin,
    reference: SemanticId,
) -> bool {
    let Some(reference_ordinal) = reference.ordinal() else {
        return false;
    };
    if fragment.ordinal() != reference_ordinal {
        return false;
    }
    match origin {
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary) => true,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedImplicitReceiver) => {
            site_semantic(fragment, source_site) == reference
        }
        LoweringGapOrigin::Extracted(ResolutionGapKind::AmbiguousQualifiedType) => {
            lexical_type_outranks_package(language)
                && site_semantic(fragment, source_site) == reference
        }
        _ => false,
    }
}

/// A proved Java type obscures a package of the same name (JLS 6.4.2 and
/// 6.5.4.1). Scala likewise ranks a binding in scope above a package member
/// (SLS chapter 2). An unproved prefix retains its other completion reasons.
const fn lexical_type_outranks_package(language: Language) -> bool {
    matches!(language, Language::Java | Language::Scala)
}

/// Java's new terminal type continuation retires only its own name ambiguity.
/// Existing prefix rules for placement or receivers are separate claims.
pub(crate) fn jvm_terminal_type_gap_origin_is_safe(
    language: Language,
    fragment: BindingFragmentId,
    source_site: ResolutionSiteId,
    origin: LoweringGapOrigin,
    reference: SemanticId,
) -> bool {
    if language == Language::Java
        && origin != LoweringGapOrigin::Extracted(ResolutionGapKind::AmbiguousQualifiedType)
    {
        return false;
    }
    jvm_type_prefix_gap_origin_is_safe(language, fragment, source_site, origin, reference)
}

pub(super) fn reference_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(site_identity_digest(
        b"bifrost-resolution-reference-semantic-local:v2",
        "site",
        site,
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
#[doc(hidden)]
pub fn mounted_site_semantic(fragment: BindingFragmentId, site: ResolutionSiteId) -> SemanticId {
    debug_assert_eq!(site_catalog_position(site), site.get());
    site_semantic(fragment, site)
}

/// The runtime node one mount gives the site numbered `site`. See
/// [`mounted_site_semantic`].
#[doc(hidden)]
pub fn mounted_site_node(fragment: BindingFragmentId, site: ResolutionSiteId) -> BindingNodeId {
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
    ResolutionSemanticIdentity::fragment_local(site_identity_digest(
        b"bifrost-resolution-definition-semantic-local:v2",
        "site",
        site,
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

#[doc(hidden)]
pub fn lookup_semantic(
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

#[doc(hidden)]
pub fn root_import_anchor_semantic_identity(
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

pub(crate) fn root_import_anchor_for_identity(
    identity: &ResolutionSemanticIdentity,
) -> Option<ResolutionRootImportAnchor> {
    [
        ResolutionRootImportAnchor::Lexical,
        ResolutionRootImportAnchor::Absolute,
    ]
    .into_iter()
    .find(|anchor| root_import_anchor_semantic_identity(*anchor) == *identity)
}

#[doc(hidden)]
pub fn root_import_token_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-import token needs an effective namespace"
    );
    ResolutionSemanticIdentity::fragment_local(site_namespace_digest(
        b"bifrost-resolution-root-import-token-local:v1",
        site,
        namespace,
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
    ResolutionSemanticIdentity::fragment_local(site_namespace_digest(
        b"bifrost-resolution-root-reference-token-local:v1",
        site,
        namespace,
    ))
}

pub(crate) fn root_export_token(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(root_export_token_identity(root_scope, namespace))
}

#[doc(hidden)]
pub fn root_export_token_identity(
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-export token needs an effective namespace"
    );
    ResolutionSemanticIdentity::fragment_local(scope_namespace_digest(
        b"bifrost-resolution-root-export-token-local:v1",
        "root_scope",
        root_scope,
        namespace,
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
    ResolutionSemanticIdentity::fragment_local(scope_namespace_digest(
        b"bifrost-resolution-scope-choice-local:v3",
        "scope",
        scope,
        namespace,
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
    ResolutionSemanticIdentity::fragment_local(scope_namespace_digest(
        b"bifrost-resolution-hierarchy-choice-local:v2",
        "scope",
        scope,
        namespace,
    ))
}

pub(super) fn reference_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> BindingNodeId {
    identities.node(reference_node_identity(site))
}

pub(crate) fn reference_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(site_identity_digest(
        b"bifrost-resolution-reference-node-local:v1",
        "site",
        site,
    ))
}

pub(crate) fn definition_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> BindingNodeId {
    identities.node(definition_node_identity(site))
}

pub(crate) fn definition_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(site_identity_digest(
        b"bifrost-resolution-definition-node-local:v1",
        "site",
        site,
    ))
}

/// The semantic that holds the catalog position of a site that mints none.
///
/// Site `n`, its semantic and its node carry one number, so catalog position
/// `n` belongs to site `n` whether or not the site has a semantic. Sites without
/// a positioned identifier mint no semantic or node; fillers keep their catalog
/// positions occupied so every other site retains its number.
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

#[doc(hidden)]
pub fn scope_head_node_identity(scope: ResolutionScopeId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(scope_identity_digest(
        b"bifrost-resolution-scope-head-node-local:v1",
        "scope",
        scope,
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
    ResolutionPathIdentity::new(scope_identity_digest(
        b"bifrost-resolution-parent-path-local:v2",
        "scope",
        scope,
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
    ResolutionPathIdentity::new(site_namespace_digest(
        b"bifrost-resolution-reference-path-local:v1",
        site,
        namespace,
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

fn activation_replay_path_identity(
    identity: ResolutionPathIdentity,
    position: usize,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-activation-replay-path:v1",
        &[
            ("path", &identity.digest()),
            ("snapshot", &usize_bytes(position)),
        ],
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
    ResolutionPathIdentity::new(site_namespace_digest(
        b"bifrost-resolution-additional-binder-path-local:v1",
        site,
        namespace,
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

#[doc(hidden)]
pub fn root_reference_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-reference path needs an effective namespace"
    );
    ResolutionPathIdentity::new(site_namespace_digest(
        b"bifrost-resolution-root-reference-path-local:v1",
        site,
        namespace,
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
    ResolutionPathIdentity::new(site_namespace_digest(
        b"bifrost-resolution-structured-import-gap-path-local:v2",
        site,
        namespace,
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
    closed_macro_member_surfaces: &HashSet<ResolutionSiteId>,
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
            identities.gap_reason(source.site, source.origin),
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
        let import_choice = identities.semantic(import_choice_identity(scope, namespace));
        precedence.extend(scope_choice_precedence(
            identities,
            scope_choice,
            &[],
            import_choice,
            namespace,
            ScopeChoice::Import,
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
    // A replay proof closes only the member branch, never lexical names.
    let open_sources = sources
        .iter()
        .filter(|source| !closed_macro_member_surfaces.contains(&source.site))
        .collect::<Vec<_>>();
    let Some(first) = open_sources.iter().map(|source| source.site).min() else {
        return;
    };
    let reason = ResolutionCompletion::incomplete(open_sources.iter().map(|source| {
        ResolutionIncompleteReason::UnsupportedSemantic(
            identities.gap_reason(source.site, source.origin),
        )
    }));
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
    let reason = identities.gap_reason(
        site,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary),
    );
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
    language: Language,
    root_scope: ResolutionScopeId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    bound_name: &str,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
    structured_import_gap_lexical_row_with_identities(
        &mut identities,
        language,
        root_scope,
        site,
        namespace,
        bound_name,
    )
}

pub(super) fn structured_import_gap_lexical_row_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    root_scope: ResolutionScopeId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    bound_name: &str,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let lookup = identities.lookup_semantic(language, namespace, bound_name);
    let sink = identities.node(structured_import_gap_sink_node_identity(site, namespace));
    let path = identities.path(structured_import_gap_path_identity(site, namespace));
    let root = identities.source_scope_node(root_scope);
    let choice = identities.semantic(scope_choice_identity(root_scope, namespace));
    let reason = identities.gap_reason(
        site,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute),
    );
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
                        // Keep the unresolved route at the same precedence as
                        // the exact import so a selected target retains the
                        // import boundary's incomplete evidence.
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

#[doc(hidden)]
pub fn gap_reason_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
) -> SemanticId {
    identities.gap_reason(site, origin)
}

pub(crate) fn gap_reason_semantic_identity(
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
            ResolutionGapKind::UnsupportedExpressionType => {
                b"extracted:unsupported-expression-type"
            }
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
    use crate::analyzer::resolution::fact_lowering::go_global_support_0::*;

    use super::fixture_names::{
        additional_binder_path_id, binder_path_id, checkpoint_choice, gap_reason_semantic,
        hierarchy_choice, hierarchy_gap_path_id, missing_binder_path_id, parent_path_id,
        placement_gap_path_id, reference_node, root_export_token, root_import_anchor_semantic,
        root_import_token, root_reference_token, scope_choice, scope_head_node,
        site_type_frontier_semantic, type_slot_semantic,
    };
    use crate::analyzer::resolution::test_support::binder;

    use brokk_bifrost_core::analyzer::resolution_facts::{
        PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
        ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
        ResolutionCallableReceiverOriginFact, ResolutionGapFact, ResolutionIdentifierRole,
        ResolutionMemberAccess, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
        ResolutionNameFact, ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact,
        ResolutionRootImportKindFact, ResolutionScopeKind, ResolutionSiteKind,
        ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeSlotFact,
        ResolutionTypeSlotRole,
    };

    use crate::CancellationToken;

    use super::super::batch::{BatchResolutionEngine, BatchResolutionFragmentSource};
    use super::super::engine::{ResolutionEngine, ResolutionQuery};
    use super::super::local_identity::{
        MountRebaser, ResolutionSemanticIdentitySpace, SelectedResolutionMountOrdinal,
        SelectedSemanticProvenance,
    };
    use super::super::lower_resolution_facts_with_identity_catalog;
    use super::super::positioned_identifier_for_test as identifier;
    use super::*;

    #[cfg(test)]
    #[test]
    fn kotlin_named_and_star_imports_have_their_language_precedence_tiers() {
        let facts = root_route_facts();
        let star = FactIndex::new(Language::Kotlin, &facts)
            .root_imports
            .into_iter()
            .next()
            .expect("root import fixture");
        let named = IndexedRootImport {
            kind: ResolutionRootImportKind::Named,
            ..star.clone()
        };
        let root_scope = ResolutionScopeId::new(1);
        let namespace = ResolutionNamespace::Type;
        let mut identities = ResolutionIdentityCatalogBuilder::new(
            fragment(),
            crate::analyzer::resolution::test_shared_names(),
        );
        let choice = identities.semantic(scope_choice_identity(root_scope, namespace));

        let named =
            root_import_precedence(&mut identities, Language::Kotlin, &named, choice, namespace);
        let star =
            root_import_precedence(&mut identities, Language::Kotlin, &star, choice, namespace);

        assert_eq!(named[0].tier, PrecedenceTier::ExplicitImport);
        assert_eq!(star[0].tier, PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::PackageOrModule);
        assert!(PrecedenceTier::PackageOrModule < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::WildcardImport < PrecedenceTier::DefaultImport);
    }

    #[cfg(test)]
    #[test]
    fn selected_java_single_import_preserves_its_unresolved_route_gap() {
        let mut facts = root_route_facts();
        let import_site = ResolutionSiteId::new(0);
        let name = ResolutionNameId::new(3);
        facts.root_import_kinds[0].kind = ResolutionRootImportKind::Named;
        facts.import_routes.push(ResolutionImportRouteFact {
            site: import_site,
            root_scope: ResolutionScopeId::new(1),
            kind: ResolutionImportRouteKind::SingleType,
            bound_name: Some(name),
        });
        facts.import_route_segments.extend((0..4).map(|ordinal| {
            ResolutionImportRouteSegmentFact {
                import_site,
                ordinal,
                name: ResolutionNameId::new(ordinal),
            }
        }));
        facts.gaps.push(ResolutionGapFact::unsupported_route(
            import_site,
            ResolutionRouteGap::UnknownBinder {
                scope: ResolutionScopeId::new(1),
                name: Some(name),
                namespace: Some(ResolutionNamespace::Type),
                may_publish: false,
            },
        ));

        let (lowered, identities) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts);
        let path = |identity| {
            let path = identities
                .path_for_identity(identity)
                .expect("Java import path identity");
            lowered
                .paths()
                .iter()
                .find(|(id, _)| *id == path)
                .map(|(_, path)| path)
                .expect("lowered Java import path")
        };
        let root_import = path(root_import_path_identity(
            import_site,
            ResolutionNamespace::Type,
            name,
        ));
        let unresolved_gap = path(structured_import_gap_path_identity(
            import_site,
            ResolutionNamespace::Type,
        ));

        assert_eq!(
            root_import.precedence()[0].tier,
            PrecedenceTier::ExplicitImport
        );
        assert_eq!(root_import.precedence()[0].ordinal, 0);
        assert_eq!(
            unresolved_gap.precedence()[0].tier,
            PrecedenceTier::ExplicitImport
        );
        assert_eq!(unresolved_gap.precedence()[0].ordinal, 0);
        assert!(matches!(
            unresolved_gap.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[cfg(test)]
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
            let reason = identities.gap_reason(
                ResolutionSiteId::new(13),
                LoweringGapOrigin::QualifiedReference,
            );
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
    #[test]
    fn lowered_reference_site_metadata_survives_every_preloaded_seed_shape() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(1),
                ResolutionGapKind::UnsupportedCallApplicability,
            )],
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(2),
                ResolutionGapKind::UnsupportedScopeOrBinder,
            )],
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(1),
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            )],
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
        facts.binders.push(ResolutionBinderFact::scope_wide(
            ResolutionSiteId::new(site_id),
            binder_kind,
            scope,
        ));
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "e977e5edd26f: default-concurrency failures exposed a process-global fixture-catalog race; the barrier pin was introduced with thread-local isolation"
    )]
    fn concurrent_fixtures_keep_catalogs_for_their_own_thread() {
        let ready = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let workers = [3, 4].map(|declaration| {
                let ready = &ready;
                scope.spawn(move || {
let _neutral_rules = crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[crate::analyzer::Language::Java]);
                    let fragment = BindingFragmentId::for_test(b"concurrent-fixture-catalog");
                    let mut facts = nested_type_body_facts(ResolutionNamespace::Callable);
                    add_scope_wide_declaration(
                        &mut facts,
                        declaration,
                        2,
                        2,
                        ResolutionSiteKind::CallableDeclaration,
                        ResolutionBinderKind::Callable,
                        ResolutionNamespace::Callable,
                    );
                    let (lowered, catalog) =
                        lower_lexical_for_test(fragment, Language::Java, &facts);
                    let site = ResolutionSiteId::new(declaration);
                    let expected_path = catalog
                        .path_for_identity(binder_path_identity(site))
                        .expect("the fixture's own catalog contains its method binder");
                    let direct = semantic(&lowered, declaration, LoweredSemanticRole::Definition);
                    // Both catalogs have been recorded before either fixture
                    // asks for its own path. A shared table loses one binder.
                    ready.wait();
                    assert_eq!(binder_path_id(fragment, site), expected_path);
                    let answer = resolve_with_coverage(lowered, 2);
                    assert_eq!(answer.targets(), &[direct]);
                })
            });
            for worker in workers {
                worker
                    .join()
                    .expect("concurrent fixture preserves its catalog");
            }
        });
    }

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(4),
                ResolutionGapKind::UnsupportedPlacementBoundary,
            )],
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

    #[cfg(test)]
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

    fn alias_scope_facts() -> FileResolutionFacts {
        let mut facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![
                scope(0, None, 0, 400),
                scope(1, Some(0), 10, 100),
                scope(2, Some(0), 110, 250),
                scope(3, Some(2), 150, 200),
                scope(4, Some(0), 260, 390),
            ],
            ..FileResolutionFacts::default()
        };
        for (id, scope_id, kind, position, role) in [
            (
                0,
                1,
                ResolutionSiteKind::ValueDeclaration,
                20,
                ResolutionIdentifierRole::Declaration,
            ),
            (
                1,
                2,
                ResolutionSiteKind::AliasBinding,
                120,
                ResolutionIdentifierRole::Alias,
            ),
            (
                2,
                2,
                ResolutionSiteKind::ValueReference,
                130,
                ResolutionIdentifierRole::Reference,
            ),
            (
                3,
                1,
                ResolutionSiteKind::ValueReference,
                30,
                ResolutionIdentifierRole::Reference,
            ),
            (
                4,
                3,
                ResolutionSiteKind::ValueReference,
                170,
                ResolutionIdentifierRole::Reference,
            ),
            (
                5,
                4,
                ResolutionSiteKind::ValueReference,
                280,
                ResolutionIdentifierRole::Reference,
            ),
            (
                6,
                3,
                ResolutionSiteKind::ValueDeclaration,
                160,
                ResolutionIdentifierRole::Declaration,
            ),
        ] {
            facts.sites.push(site(id, scope_id, kind, position));
            facts
                .identifiers
                .push(identifier(id, 0, role, ResolutionNamespace::Value));
        }
        for (id, scope_id, kind, start, end) in [
            (0, 1, ResolutionBinderKind::Parameter, 10, 100),
            (
                1,
                2,
                ResolutionBinderKind::Alias {
                    target: ResolutionSiteId::new(0),
                },
                110,
                250,
            ),
            (6, 3, ResolutionBinderKind::Parameter, 150, 200),
        ] {
            facts.binders.push(binder(
                id,
                scope_id,
                kind,
                HoistingClass::ScopeWide,
                start,
                end,
            ));
        }
        facts
    }

    #[cfg(test)]
    #[test]
    fn alias_scopes_preserve_canonical_lookup_shadowing_and_inventory() {
        let facts = alias_scope_facts();
        let (lowered, _) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts);
        let target = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let nested = semantic(&lowered, 6, LoweredSemanticRole::Definition);
        // This is the declaration inventory consumed by publication and the
        // native declaration bridge: the alias has no semantic or node.
        let definitions = lowered
            .semantics()
            .iter()
            .filter(|site| site.role() == LoweredSemanticRole::Definition)
            .map(|site| site.site())
            .collect::<HashSet<_>>();
        assert_eq!(
            definitions,
            [ResolutionSiteId::new(0), ResolutionSiteId::new(6)]
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert!(
            lowered
                .semantics()
                .iter()
                .all(|site| site.site() != ResolutionSiteId::new(1))
        );
        for (reference, expected) in [
            (2, vec![target]),
            (3, vec![target]),
            (4, vec![nested]),
            (5, vec![]),
        ] {
            let answer = resolve_with_coverage(lowered.clone(), reference);
            assert_eq!(answer.targets(), expected, "reference {reference}");
            assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        }
        let alias_reference = semantic(&lowered, 2, LoweredSemanticRole::Reference);
        let own_reference = semantic(&lowered, 3, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let reverse = BatchResolutionEngine::new(&source)
            .references_to(target, &CancellationToken::new())
            .expect("alias reverse lookup");
        assert_eq!(
            reverse.references().iter().copied().collect::<HashSet<_>>(),
            [alias_reference, own_reference]
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert_eq!(reverse.completion(), &ResolutionCompletion::Complete);

        let mut tied = facts;
        tied.sites
            .push(site(7, 2, ResolutionSiteKind::ValueDeclaration, 140));
        tied.identifiers.push(identifier(
            7,
            0,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        ));
        tied.binders.push(binder(
            7,
            2,
            ResolutionBinderKind::Local,
            HoistingClass::ScopeWide,
            110,
            250,
        ));
        let (lowered, _) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &tied);
        let same_scope = semantic(&lowered, 7, LoweredSemanticRole::Definition);
        let target = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let answer = resolve_with_coverage(lowered, 2);
        assert_eq!(
            answer.targets().iter().copied().collect::<HashSet<_>>(),
            [target, same_scope].into_iter().collect::<HashSet<_>>()
        );
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5909: typed binder validation treated alias binding sites as declarations"
    )]
    fn alias_reference_preserves_the_targets_declared_type_through_full_lowering() {
        use crate::analyzer::resolution::test_support::{slot, transfer};
        use brokk_bifrost_core::analyzer::resolution_facts::{
            BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole,
            DeclarationTypeSlotFact, IntrinsicTypeKind, IntrinsicTypeSeedFact,
            ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
        };

        let mut facts = alias_scope_facts();
        facts.names.push(ResolutionNameFact {
            id: ResolutionNameId::new(1),
            spelling: "int".into(),
        });
        facts
            .sites
            .push(site(7, 1, ResolutionSiteKind::TypeReference, 21));
        facts.type_slots = vec![
            slot(0, 7, ResolutionTypeSlotRole::TargetTypeIdentity),
            slot(1, 0, ResolutionTypeSlotRole::DeclaredValue),
            slot(2, 2, ResolutionTypeSlotRole::ExpressionValue),
        ];
        facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: ResolutionTypeSlotId::new(0),
            name: ResolutionNameId::new(1),
            kind: IntrinsicTypeKind::Primitive,
            indirection: 0,
        });
        facts.type_transfers.push(transfer(
            0,
            1,
            ResolutionTypeTransferKind::DeclaredType,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        ));
        facts.declaration_type_slots.push(DeclarationTypeSlotFact {
            declaration: ResolutionSiteId::new(0),
            slot: ResolutionTypeSlotId::new(1),
            role: DeclarationTypeRole::Value,
        });
        facts.binding_projections.push(BindingProjectionFact {
            reference: ResolutionSiteId::new(2),
            output: ResolutionTypeSlotId::new(2),
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts);
        let target = semantic(lowered.lexical(), 0, LoweredSemanticRole::Definition);
        let reference = semantic(lowered.lexical(), 2, LoweredSemanticRole::Reference);
        assert_eq!(lowered.typed().declaration_types().len(), 1);
        assert_eq!(lowered.typed().declaration_types()[0].definition(), target);
        let expected_type = lowered.typed().intrinsic_seeds()[0]
            .frontier()
            .possible_values()[0]
            .ty()
            .identity();
        let source =
            crate::analyzer::resolution::PreloadedFactResolutionService::from_lowered_fragments(
                [lowered.lexical().clone()],
                [lowered.typed().clone()],
            );
        let answer = source
            .resolve_reference(reference, &CancellationToken::new())
            .expect("resolve declared type through an alias");
        assert_eq!(answer.binding().targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        assert_eq!(answer.projected_frontiers().len(), 1);
        let frontier = &answer.projected_frontiers()[0];
        assert_eq!(frontier.completion(), &ResolutionCompletion::Complete);
        assert_eq!(frontier.possible_values().len(), 1);
        assert_eq!(frontier.possible_values()[0].ty().identity(), expected_type);
    }

    #[cfg(test)]
    #[test]
    fn alias_lowering_rejects_invalid_targets_names_and_scopes() {
        type InvalidFact = (&'static str, fn(&mut FileResolutionFacts));
        let invalid: &[InvalidFact] = &[
            ("unknown target", |facts| {
                facts.binders[1].kind = ResolutionBinderKind::Alias {
                    target: ResolutionSiteId::new(99),
                }
            }),
            ("reference target", |facts| {
                facts.binders[1].kind = ResolutionBinderKind::Alias {
                    target: ResolutionSiteId::new(3),
                }
            }),
            ("alias chain", |facts| {
                facts.binders[1].kind = ResolutionBinderKind::Alias {
                    target: ResolutionSiteId::new(1),
                }
            }),
            ("renamed alias", |facts| {
                facts.names.push(ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "y".into(),
                });
                facts.identifiers[1].name = ResolutionNameId::new(1);
            }),
            ("different namespace", |facts| {
                facts.identifiers[1].namespace = ResolutionNamespace::Type
            }),
            ("qualified alias", |facts| {
                facts.identifiers[1].qualifier = Some(ResolutionTypeSlotId::new(0))
            }),
            ("non-alias identifier", |facts| {
                facts.identifiers[1].role = ResolutionIdentifierRole::Declaration
            }),
            ("non-alias site", |facts| {
                facts.sites[1].kind = ResolutionSiteKind::ValueDeclaration
            }),
            ("wrong alias scope", |facts| {
                facts.sites[1].scope = ResolutionScopeId::new(0)
            }),
            ("ordinary cross-scope binder", |facts| {
                facts.sites[0].scope = ResolutionScopeId::new(0)
            }),
        ];
        for &(description, mutate) in invalid {
            let mut facts = alias_scope_facts();
            mutate(&mut facts);
            assert!(
                std::panic::catch_unwind(|| {
                    crate::analyzer::resolution::lower_lexical_for_test(
                        fragment(),
                        Language::Java,
                        &facts,
                    )
                })
                .is_err(),
                "accepted {description}"
            );
        }
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(2),
                ResolutionGapKind::UnsupportedPlacementBoundary,
            )],
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

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5205: generated item surfaces must keep missing lexical names open"
    )]
    fn semantic_only_rust_gaps_retain_target_scoped_reverse_coverage() {
        let member_scope = ResolutionGapKind::UnsupportedMemberScope;
        let generated_surface = ResolutionGapKind::GeneratedItemSurface;
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::UnsupportedDeclaration, 20),
                site(1, 0, ResolutionSiteKind::UnsupportedDeclaration, 40),
            ],
            gaps: vec![
                ResolutionGapFact::new(ResolutionSiteId::new(0), member_scope),
                ResolutionGapFact::new(ResolutionSiteId::new(1), generated_surface),
            ],
            ..FileResolutionFacts::default()
        };
        let (lowered, identities) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts);
        let expected = [LoweringCoverageFrontier::CandidateInventory {
            direction: LoweredCandidateDirection::Reverse,
        }]
        .into_iter()
        .collect::<HashSet<_>>();
        for (site, kind) in [
            (ResolutionSiteId::new(0), member_scope),
            (ResolutionSiteId::new(1), generated_surface),
        ] {
            let actual = lowered
                .gaps()
                .iter()
                .filter(|gap| {
                    gap.site() == site && gap.origin() == LoweringGapOrigin::Extracted(kind)
                })
                .map(LoweredCoverageGap::frontier)
                .collect::<HashSet<_>>();
            let mut expected = expected.clone();
            if kind == generated_surface {
                expected.clear();
                expected.insert(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint: identities
                        .node_for_identity(scope_head_node_identity(ResolutionScopeId::new(0)))
                        .expect("the lexical scope is registered"),
                    lookup: None,
                });
            }
            assert_eq!(actual, expected, "semantic-only gap at {site:?}");
        }
    }

    #[cfg(test)]
    #[test]
    fn unknown_placement_without_affirmative_rows_retains_fragment_and_enumeration_gaps() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedRoute, 20)],
            gaps: vec![ResolutionGapFact::unsupported_route(
                ResolutionSiteId::new(0),
                ResolutionRouteGap::UnknownPlacement,
            )],
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

    #[cfg(test)]
    #[test]
    fn unsupported_expression_blocks_enumeration_but_not_fragment_candidates() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedExpression,
            )],
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

    #[cfg(test)]
    #[test]
    #[hardwon(
        "18b74c827c06: completed native comparison exposed fragment-wide uncertainty on positioned local calls; dedicated member-scope evidence fixed the wrong proof boundary"
    )]
    fn member_scope_gap_preserves_lexical_points_but_keeps_reverse_open() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Rust,
            ]);
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(2),
                ResolutionGapKind::UnsupportedMemberScope,
            )],
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

    #[cfg(test)]
    #[test]
    fn unsupported_type_subtree_blocks_enumeration_and_reverse_inventory() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedTypeSyntax,
            )],
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedExpression,
            )],
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

    #[cfg(test)]
    #[test]
    fn reference_enumeration_gap_is_independent_of_point_resolution_gaps() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedExpression,
            )],
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(row.site, row.kind)],
            reference_enumeration_gaps: vec![row, row],
            ..FileResolutionFacts::default()
        };
        let _ =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
    }

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedVisibility,
            )],
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(1),
                ResolutionGapKind::UnsupportedImplicitReceiver,
            )],
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

    #[cfg(test)]
    #[test]
    fn qualified_reference_scopes_reverse_incompleteness_to_its_terminal_lookup() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "member".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "unrelated".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::MemberReference, 20),
                site(2, 0, ResolutionSiteKind::TypeDeclaration, 40),
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
                PositionedIdentifierFact {
                    site: ResolutionSiteId::new(2),
                    name: ResolutionNameId::new(1),
                    role: ResolutionIdentifierRole::Declaration,
                    namespace: ResolutionNamespace::Type,
                    qualifier: None,
                },
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
                && matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint,
                        lookup: Some(_),
                    } if endpoint == BindingNodeId::universal_root()
                )
        }));
        let local_scope = scope_head_node(fragment(), ResolutionScopeId::new(0));
        assert!(lowered.gaps().iter().any(|gap| {
            gap.origin() == LoweringGapOrigin::QualifiedReference
                && matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint,
                        lookup: Some(_),
                    } if endpoint == local_scope
                )
        }));
        assert!(!lowered.gaps().iter().any(|gap| {
            gap.origin() == LoweringGapOrigin::QualifiedReference
                && matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::CandidateInventory { .. }
                )
        }));
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let unrelated_definition = semantic(&lowered, 2, LoweredSemanticRole::Definition);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut engine = BatchResolutionEngine::new(&source);
        let answer = engine
            .references_to(definition, &CancellationToken::new())
            .expect("reverse qualified lookup");
        assert!(answer.references().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
        let unrelated_answer = engine
            .references_to(unrelated_definition, &CancellationToken::new())
            .expect("reverse unrelated lookup");
        assert!(unrelated_answer.references().is_empty());
        assert_eq!(
            unrelated_answer.completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(1),
                ResolutionGapKind::UnsupportedPlacementBoundary,
            )],
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(1),
                ResolutionGapKind::UnsupportedPlacementBoundary,
            )],
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                boundary,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            )],
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

    #[cfg(test)]
    #[test]
    fn unqualified_lookup_crossing_an_open_type_hierarchy_is_incomplete() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            )],
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
                parent_ordinal: 0,
                supertype_reference: ResolutionSiteId::new(2),
                supertype_slot: ResolutionTypeSlotId::new(0),
                kind,
            }],
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(2),
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            )],
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

    #[cfg(test)]
    #[test]
    fn explicit_class_supertype_keeps_empty_and_enclosing_lookup_incomplete() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Superclass,
            false,
        );
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Superclass,
            true,
        );
    }

    #[cfg(test)]
    #[test]
    fn explicit_interface_supertype_keeps_empty_and_enclosing_lookup_incomplete() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Interface,
            false,
        );
        assert_explicit_supertype_hierarchy_is_incomplete(ResolutionSupertypeKind::Interface, true);
    }

    #[cfg(test)]
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
                    parent_ordinal: 0,
                    supertype_reference: ResolutionSiteId::new(1),
                    supertype_slot: ResolutionTypeSlotId::new(0),
                    kind: ResolutionSupertypeKind::Superclass,
                },
                ResolutionSupertypeFact {
                    subtype: ResolutionSiteId::new(0),
                    parent_ordinal: 1,
                    supertype_reference: ResolutionSiteId::new(2),
                    supertype_slot: ResolutionTypeSlotId::new(1),
                    kind: ResolutionSupertypeKind::Interface,
                },
            ],
            gaps: vec![
                ResolutionGapFact::new(
                    ResolutionSiteId::new(1),
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                ),
                ResolutionGapFact::new(
                    ResolutionSiteId::new(2),
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                ),
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

    #[cfg(test)]
    #[test]
    fn inherited_reference_gap_keeps_reverse_lookup_of_base_definition_incomplete() {
        let _neutral_rules =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
                crate::analyzer::Language::Java,
            ]);
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(0),
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            )],
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

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: SB census binder expiration must preserve other active declarations"
    )]
    fn bounded_declared_head_preserves_surviving_source_order_and_other_binders() {
        let mut facts = FileResolutionFacts {
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
            ..FileResolutionFacts::default()
        };
        for (id, name, position, hoisting, start, end) in [
            (0, 0, 1, HoistingClass::ScopeWide, 0, 100),
            (1, 1, 2, HoistingClass::ScopeWide, 0, 100),
            (2, 0, 3, HoistingClass::DeclaredHead, 10, 30),
            (3, 1, 4, HoistingClass::DeclaredHead, 15, 40),
            (4, 0, 5, HoistingClass::SourceOrder, 20, 100),
        ] {
            facts
                .sites
                .push(site(id, 0, ResolutionSiteKind::ValueDeclaration, position));
            facts.identifiers.push(identifier(
                id,
                name,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            ));
            facts.binders.push(binder(
                id,
                0,
                ResolutionBinderKind::Local,
                hoisting,
                start,
                end,
            ));
        }
        let cases = [
            (5, 0, 11, 2),
            (6, 0, 25, 4),
            (7, 0, 35, 4),
            (8, 1, 35, 3),
            (9, 1, 45, 1),
        ];
        for (id, name, position, _) in cases {
            facts
                .sites
                .push(site(id, 0, ResolutionSiteKind::ValueReference, position));
            facts.identifiers.push(identifier(
                id,
                name,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            ));
        }
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
        assert!(lowered.gaps().is_empty());
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments(
                [lowered.clone()],
            );
        let engine = BatchResolutionEngine::new(&source);
        for (id, _, position, target) in cases {
            let reference = semantic(&lowered, id, LoweredSemanticRole::Reference);
            let definition = semantic(&lowered, target, LoweredSemanticRole::Definition);
            let answer = engine
                .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
                .unwrap();
            assert_eq!(answer.targets(), &[definition], "position {position}");
            assert_eq!(
                answer.completion(),
                &ResolutionCompletion::Complete,
                "position {position}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn unsupported_source_order_end_does_not_taint_an_unrelated_lookup() {
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
                    HoistingClass::SourceOrder,
                    0,
                    50,
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
                    == LoweringGapOrigin::UnsupportedActivation(HoistingClass::SourceOrder) =>
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

    #[cfg(test)]
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
            gaps: vec![ResolutionGapFact::new(
                ResolutionSiteId::new(2),
                ResolutionGapKind::AmbiguousNumericLiteral,
            )],
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

    #[cfg(test)]
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
                parent_ordinal: 0,
                supertype_reference: ResolutionSiteId::new(3),
                supertype_slot: ResolutionTypeSlotId::new(0),
                kind: ResolutionSupertypeKind::Superclass,
            }],
            gaps: vec![
                ResolutionGapFact::new(
                    ResolutionSiteId::new(2),
                    ResolutionGapKind::ImplicitConstructor,
                ),
                ResolutionGapFact::new(
                    ResolutionSiteId::new(3),
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                ),
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_global_support_0 {
    use crate::CancellationToken;
    use crate::analyzer::resolution::batch::{
        BatchResolutionEngine, BatchResolutionFragmentSource,
    };
    use crate::analyzer::resolution::engine::{ResolutionEngine, ResolutionQuery};
    use crate::analyzer::resolution::fact_lowering::fixture_names::{
        additional_binder_path_id, binder_path_id, checkpoint_choice, gap_reason_semantic,
        hierarchy_choice, hierarchy_gap_path_id, missing_binder_path_id, parent_path_id,
        placement_gap_path_id, reference_node, root_export_token, root_import_anchor_semantic,
        root_import_token, root_reference_token, scope_choice, scope_head_node,
        site_type_frontier_semantic, type_slot_semantic,
    };
    use crate::analyzer::resolution::fact_lowering::*;
    use crate::analyzer::resolution::local_identity::{
        MountRebaser, ResolutionSemanticIdentitySpace, SelectedResolutionMountOrdinal,
        SelectedSemanticProvenance,
    };
    use crate::analyzer::resolution::lower_resolution_facts_with_identity_catalog;
    use crate::analyzer::resolution::positioned_identifier_for_test as identifier;
    use crate::analyzer::resolution::test_support::binder;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
        ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
        ResolutionCallableReceiverOriginFact, ResolutionGapFact, ResolutionIdentifierRole,
        ResolutionMemberAccess, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
        ResolutionNameFact, ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact,
        ResolutionRootImportKindFact, ResolutionScopeKind, ResolutionSiteKind,
        ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeSlotFact,
        ResolutionTypeSlotRole,
    };
    #[doc(hidden)]
    pub fn fragment() -> BindingFragmentId {
        BindingFragmentId::for_test(b"fact-lowering-test-fragment")
    }
    #[doc(hidden)]
    pub fn root_route_facts() -> FileResolutionFacts {
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
                position: None,
            }],
            root_import_kinds: vec![ResolutionRootImportKindFact {
                import_site,
                kind: ResolutionRootImportKind::Glob,
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
                owner_continued: false,
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
    #[doc(hidden)]
    pub fn scope(
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
    #[doc(hidden)]
    pub fn site(
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
    #[doc(hidden)]
    pub fn semantic(
        lowered: &LoweredResolutionFragment,
        site: u32,
        role: LoweredSemanticRole,
    ) -> SemanticId {
        crate::analyzer::resolution::test_support::lowered_semantic_at(
            lowered.semantics(),
            ResolutionSiteId::new(site),
            role,
        )
    }
    #[doc(hidden)]
    pub fn resolve_with_coverage(
        lowered: LoweredResolutionFragment,
        reference_site: u32,
    ) -> crate::analyzer::resolution::model::ResolutionAnswer {
        let reference = semantic(&lowered, reference_site, LoweredSemanticRole::Reference);
        let source =
            crate::analyzer::resolution::engine::PreloadedFragmentSource::from_lowered_fragments([
                lowered,
            ]);
        BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution with normalized coverage")
    }
}
