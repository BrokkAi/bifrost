//! Compositional name and member resolution over immutable file-local facts.
//!
//! This module owns the operation-local algebra and stitcher. Persistence and
//! language lowering are deliberately separate: both the preload test source
//! and the eventual SQL source present the same normalized fragment contract.

mod batch;
mod common_fact_lowering;
mod completion_reasons;
mod demand_overlay;
mod engine;
mod fact_lowering;
mod fact_reference_edges;
mod fact_resolution;
mod fact_source;
#[cfg(test)]
mod language_spike;
mod local_identity;
mod model;
mod mounted;
mod remount;
mod saturation;
pub mod seam_profile;
pub mod seed_key_profile;
mod selected_context;
mod typed_fact_lowering;
mod universe;

use crate::hash::HashSet;

fn never_cancelled() -> bool {
    false
}

pub use batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
    BatchResolutionEngine, BatchResolutionFragmentSource, BatchedReferenceAnswer,
    CandidatePathIdentity, FactReferenceSiteMetadata, MAX_REFERENCE_SEEDS_PER_BATCH,
    ReferenceBatchAnswer, ReferenceSeed, ReferenceSeedBatch, ReferenceSeedReadOutcome,
    ReferenceSeedReadTerminal, ResolutionBatchMetrics, ResolutionBatchSummary,
    ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity, ReverseReferenceSeedRequest,
    SeedReadAuthority, SeededPartialPath, SeededReferenceRequest,
};
pub(crate) use batch::{
    MAX_REVERSE_TARGETS_PER_BATCH, MAX_SOURCE_ROWS_PER_BATCH, ReverseCandidateGapCoverage,
    ReverseCandidateGapCoverageBuilder, ReverseCandidateGapCoverageView,
    ReverseCandidateGapLocation, ReverseCandidateGapRow, SelectedContextPathFragmentSource,
};
pub use common_fact_lowering::LoweredDeferredMemberOwner;
pub(crate) use common_fact_lowering::LoweredRootImportProvenance;
pub use completion_reasons::CompletionReasons;
pub(crate) use demand_overlay::DemandSelectedOverlayBlueprint;
pub use engine::{
    PreloadedFragment, PreloadedFragmentSource, ReferenceSearchAnswer, ResolutionEngine,
    ResolutionFragmentSource, ResolutionQuery,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::fixture_names::{
    FixtureRootImportAnchors, record as record_fixture_identity_catalog,
};
pub(crate) use fact_lowering::package::{
    LoweredGoPackageImport, LoweredPackageMember, LoweredPackageReference,
};
pub use fact_lowering::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweredResolutionFragment, LoweredSemanticRole,
    LoweredSemanticSite, LoweringCoverageFrontier, LoweringGapOrigin,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::{
    catalog_node, catalog_semantic, lower_for_test, lower_lexical_for_test,
};
pub(crate) use fact_lowering::{
    definition_node, definition_node_identity, definition_semantic, gap_reason_semantic,
    hierarchy_terminal_node_identity, lookup_semantic, mounted_site_node, mounted_site_semantic,
    placement_gap_path_id, reference_node_identity, reference_semantic, root_export_path_id,
    scope_head_node, scope_head_node_identity, structured_import_gap_path_id,
};
pub(crate) use fact_lowering::{
    root_export_token, root_import_anchor_semantic_identity, root_import_token,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_reference_edges::validate_selected_reference_edge_coverage;
pub use fact_reference_edges::{
    FactCallableReceiverTargetAdmission, FactCallableReceiverTargetProjection,
    FactReferenceBindingShape, FactReferenceEdgeBatch, FactReferenceEdgeCatalog,
    FactReferenceEdgeDeclarationDomain, FactReferenceEdgeDomainStatus, FactReferenceEdgeGap,
    FactReferenceEdgeGapDomain, FactReferenceEdgeSelectedFragment, FactReferenceEdgeSummary,
    FactReferenceGraphAdmission, FactReferenceProjectionStatus, FactReferenceTargetProjection,
    classify_fact_reference_binding, fact_callable_receiver_target_admission,
    project_fact_callable_receiver_target, project_fact_reference_edge_batch,
    project_fact_reference_targets, stage_selected_reference_edge_batches,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_reference_edges::{
    SelectedReferenceInverseIndex, SelectedReferenceInverseIndexBuildOutcome,
    build_selected_reference_inverse_index,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::PreloadedFactResolutionService;
pub(crate) use fact_resolution::{
    DemandAcyclicOutcome, DemandRootDiscovery, DemandRootPlan, DemandRootProvider,
    DemandRootUnavailableReason, FactDemandResolution,
};
pub use fact_resolution::{
    FactBatchedReferenceAnswer, FactCallableReceiverChannels, FactCallableReceiverDisposition,
    FactCallableReceiverTargetDisposition, FactReadSession, FactReferenceBatchAnswer,
    FactReferenceReceiverGap, FactResolutionAnswer, FactResolutionBatchSummary,
    FactReverseReferenceBinding, FactReverseResolutionMetrics, FactTargetReferenceAnswer,
    FactTargetReferenceBatchAnswer, SelectedFactResolutionEngine, SelectedFactResolutionSnapshot,
};
pub(crate) use fact_resolution::{
    FactIntrinsicTypeDescriptor, FactResolutionOperation, PolledCompletionAccumulator,
    SelectedFactOperationBlueprint, SelectedFactOperationBlueprintConstruction,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::{
    reset_reverse_fact_evaluation_count_for_test, reverse_fact_evaluation_count_for_test,
};
#[cfg(test)]
pub(crate) use fact_resolution::{
    reset_selected_fact_operation_construction_count_for_test,
    selected_fact_operation_construction_count_for_test,
};
pub(crate) use fact_source::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow,
    RustDeclarationContextSource, RustReferenceContextSource, SelectedDeclarationAccessSource,
};
pub use fact_source::{
    DeferredMemberOwnerLookupName, FactPageVisitor, FactReadOutcome, FactReadTerminal, FactRequest,
    FactResolutionSource, GoMemberDeclaration, GoMemberDeclarationKind, GoStructField,
    JavaAccessEndpoint, JavaInheritanceDeclaration, JavaInheritanceDeclarationKind,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, MAX_FACT_REQUESTS_PER_BATCH,
    MAX_FACT_ROWS_PER_PAGE, MAX_TYPED_FACT_REQUESTS_PER_BATCH, MAX_TYPED_FACT_ROWS_PER_PAGE,
    QualifiedRouteSlotLookup, RustImplementedTraits, SelectedFactRow, SelectedGapReasonProvenance,
    SelectedQualifiedRoute, SelectedTypeFrontierCompletion, SelectedTypedFactSource,
    SelectedTypedRow, TypedFactPageVisitor, TypedFactReadOutcome, TypedFactReadTerminal,
    TypedFactRequest,
};
pub(crate) use local_identity::ResolutionRegisteredIdentities;
pub(crate) use local_identity::SUPPLEMENTAL_LOCAL_KEY_BASE;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use local_identity::test_shared_names;
pub(crate) use local_identity::{
    MountRebaser, MountRebaserRegistration, ResolutionIdentityCatalog,
    ResolutionIdentityCatalogBuilder, ResolutionLocalKey, ResolutionLookupSemanticRecipe,
    ResolutionNodeIdentity, ResolutionPathIdentity, ResolutionSemanticIdentity,
    ResolutionSemanticIdentitySpace, ResolutionStackVariableIdentity,
    SelectedLocalIdentityProvenance, SelectedNodeMount, SelectedNodeProvenance,
    SelectedResolutionFragmentDigest, SelectedResolutionMount, SelectedResolutionMountOrdinal,
    SelectedSemanticLocator, SelectedSemanticMount, SelectedSemanticProvenance,
    SelectedStageIdentityProvenance, selected_resolution_fragment_id,
};
pub use local_identity::{PerRequestSharedNames, SharedNameInterner};
pub use model::{
    BindingCandidateAdmission, BindingFragmentId, BindingNodeId, BindingNodeKind, CompletionReason,
    DerivationKey, EndpointSignature, GoDefinitionNamespaces, PartialPath, PartialPathId,
    PartialScopedSymbol, PrecedenceStep, ResolutionAnswer, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionSlotValue, ResolutionTypeRef, ResolutionWitness,
    ScopeStackPattern, SemanticId, SharedNameId, StackPattern, StackVariable, StackVariableId,
    SymbolStackPattern, TypeTransferRule, TypeTransferValueTransform, TypedFrontierState,
    WitnessStep,
};
pub(crate) use model::{ResolutionCompletionAccumulator, combine_completion_with_poll};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use mounted::OperationBlind;
pub(crate) use mounted::{Mounted, SpliceMount, into_interior, out_of_interior};
pub(crate) use remount::retarget_lexical;
pub(crate) use seam_profile::SeamProfiled;
pub(crate) use selected_context::{
    CatalogRootImportAnchors, SelectedContextIdentities, SelectedContextOverlay,
    SelectedContextOverlayCompilation, SelectedContextPathPublication,
    SelectedContextPathPublicationOutcome, SelectedContextPathSource, SelectedContextPathToken,
    SelectedResolutionContextInputs, SelectedResolutionContextSet,
    SelectedResolutionContextValidationOutcome, SelectedResolutionMountContext,
    SelectedRootBridgeDescriptor, SelectedRootBridgeProjection, SelectedRootImportAnchors,
    SelectedRootPathHalf, classify_selected_root_path_half, compile_selected_context_overlay,
    compile_selected_context_overlay_in_session, compile_selected_root_bridge,
    visit_selected_root_export_half_pages, visit_selected_root_import_half_pages,
};
pub(crate) use selected_context::{
    SelectedGoImportBindingDescriptor, SelectedPackageBridgeDescriptor,
};
pub use typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableParameterProperty,
    LoweredCallableResultBinding, LoweredCallableResultTypeProperty,
    LoweredCallableSignatureProperty, LoweredConstructionRequirementProperty,
    LoweredDeclarationTypeProperty, LoweredDeclarationVisibilityProperty,
    LoweredDefinitionPropertyGap, LoweredIntrinsicSeed, LoweredMemberOwnerProperty,
    LoweredMemberScopeProperty, LoweredQualifiedSeededRoute, LoweredSupertypeProperty,
    LoweredTypeComponent, LoweredTypeTransfer, LoweredTypedFragment, LoweredTypedFrontier,
    LoweredUnderlyingType,
};
#[cfg(test)]
pub(crate) fn rich_java_resolution_facts_for_test()
-> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts {
    const SOURCE: &str = r#"
package com.acme;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Outer extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;
    let root = std::env::current_dir().expect("test working directory");
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(root, "RichResolution.java");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must match the shared tree-sitter runtime");
    let tree = parser
        .parse(SOURCE, None)
        .expect("rich Java resolution fixture must parse");
    brokk_bifrost_jvm::java::declarations::parse_java_file(&file, SOURCE, &tree).resolution_facts
}

/// One source-lowered resolution artifact and the complete content identity
/// catalog needed to persist its mounted in-memory IDs as local recipes.
#[derive(Debug)]
pub(crate) struct LoweredResolutionFactsWithIdentityCatalog {
    lexical: LoweredResolutionFragment,
    typed: LoweredTypedFragment,
    common: common_fact_lowering::LoweredCommonFacts,
    identities: Box<ResolutionIdentityCatalog>,
}

fn binder_namespace_matches_kind(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionBinderKind, ResolutionNamespace,
    };

    match kind {
        ResolutionBinderKind::Type => namespace == ResolutionNamespace::Type,
        ResolutionBinderKind::Callable => namespace == ResolutionNamespace::Callable,
        ResolutionBinderKind::Constructor => namespace == ResolutionNamespace::Constructor,
        ResolutionBinderKind::Field
        | ResolutionBinderKind::Local
        | ResolutionBinderKind::Parameter
        | ResolutionBinderKind::Pattern => namespace == ResolutionNamespace::Value,
        ResolutionBinderKind::Import => namespace != ResolutionNamespace::TypeOrValue,
        ResolutionBinderKind::Macro => namespace == ResolutionNamespace::Macro,
    }
}

fn declaration_namespace_matches_site_kind(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteKind};

    match namespace {
        ResolutionNamespace::Type => matches!(
            kind,
            ResolutionSiteKind::TypeDeclaration | ResolutionSiteKind::TypeAliasDeclaration
        ),
        ResolutionNamespace::Value => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::Callable => kind == ResolutionSiteKind::CallableDeclaration,
        ResolutionNamespace::Constructor => kind == ResolutionSiteKind::ConstructorDeclaration,
        ResolutionNamespace::Macro => kind == ResolutionSiteKind::MacroDeclaration,
        ResolutionNamespace::Constant => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::TypeOrValue | ResolutionNamespace::Package => false,
    }
}

fn producer_declares_definition_namespace(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    declaration: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    hoisting: brokk_bifrost_core::analyzer::structural::resolution::HoistingClass,
) -> bool {
    facts.additional_definition_namespaces.iter().any(|fact| {
        fact.declaration == declaration && fact.namespace == namespace && fact.hoisting == hoisting
    })
}

fn binder_namespace_is_declared(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    binder: brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    binder_namespace_matches_kind(binder.kind, namespace)
        || producer_declares_definition_namespace(
            facts,
            binder.declaration,
            namespace,
            binder.hoisting,
        )
}

fn declaration_namespace_is_declared(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    declaration: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
    primary_namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    (primary_namespace == namespace && declaration_namespace_matches_site_kind(kind, namespace))
        || facts
            .additional_definition_namespaces
            .iter()
            .any(|fact| fact.declaration == declaration && fact.namespace == namespace)
}

#[cfg(test)]
impl LoweredResolutionFactsWithIdentityCatalog {
    pub(crate) fn clone_for_stage_admission_test(&self) -> Self {
        Self {
            lexical: fact_lowering::LoweredResolutionFragment::new(
                self.lexical.fragment(),
                self.lexical.language(),
                self.lexical.nodes().to_vec(),
                self.lexical.paths().to_vec(),
                self.lexical.semantics().to_vec(),
                self.lexical.gaps().to_vec(),
            ),
            typed: self.typed.clone(),
            common: self.common.clone(),
            identities: self.identities.clone(),
        }
    }

    /// Constructor extension of a real capsule, before publication. The parsed
    /// macro itself need not emit a stack variable.
    pub(crate) fn with_open_variable_for_publication_test(mut self) -> Self {
        let variable = self.identities.register_variable_for_publication_test();
        let selected = self
            .identities
            .paths()
            .iter()
            .min_by_key(|(_, identity)| *identity)
            .unwrap()
            .0;
        let mut paths = self.lexical.paths().to_vec();
        let (_, path) = paths
            .iter_mut()
            .find(|(identity, _)| *identity == selected)
            .unwrap();
        let endpoint = |value: &EndpointSignature| {
            EndpointSignature::new_scoped(
                value.node(),
                StackPattern::open(value.symbols().fixed().to_vec(), variable),
                value.scopes().clone(),
            )
        };
        *path = PartialPath::new(
            endpoint(path.start()),
            endpoint(path.end()),
            path.precedence().to_vec(),
            path.witness().to_vec(),
            path.completion().clone(),
        );
        self.lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            self.lexical.nodes().to_vec(),
            paths,
            self.lexical.semantics().to_vec(),
            self.lexical.gaps().to_vec(),
        );
        self.rekey_dense()
    }

    pub(crate) fn with_changed_reference_end_for_publication_test(&self) -> Self {
        let mut semantics = self.lexical.semantics().to_vec();
        let index = semantics
            .iter()
            .position(|site| site.site_metadata().is_some())
            .expect("fixture has an actual reference");
        let site = &semantics[index];
        let metadata = site.site_metadata().unwrap();
        let changed = FactReferenceSiteMetadata::new(
            metadata.site(),
            metadata.namespace(),
            metadata.site_kind(),
            metadata.start_byte(),
            metadata.end_byte() + 1,
            metadata.unqualified(),
            metadata.reference_owner(),
            metadata.callable_receiver_origin(),
        )
        .with_go_spelling_namespace(metadata.go_spelling_namespace())
        .with_go_package_qualifier(metadata.go_package_qualifier());
        semantics[index] = fact_lowering::LoweredSemanticSite::new(
            site.site(),
            site.namespace(),
            site.role(),
            site.semantic(),
            site.node(),
            Some(changed),
        )
        .with_go_definition_namespaces(site.go_definition_namespaces());
        let lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            self.lexical.nodes().to_vec(),
            self.lexical.paths().to_vec(),
            semantics,
            self.lexical.gaps().to_vec(),
        );
        Self {
            lexical,
            typed: self.typed.clone(),
            common: self.common.clone(),
            identities: self.identities.clone(),
        }
        .rekey_dense()
    }

    pub(crate) fn with_generic_node_payloads_for_publication_test(mut self) -> Self {
        let local = self
            .identities
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_none())
            .unwrap()
            .0;
        let shared = self
            .identities
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_some())
            .unwrap()
            .0;
        let scope = self.identities.register_node_for_publication_test(0);
        let catalog_only = self.identities.register_node_for_publication_test(1);
        let mut nodes = self.lexical.nodes().to_vec();
        nodes.push((scope, BindingNodeKind::Scope));
        let kinds = [
            BindingNodeKind::PushSymbol(local),
            BindingNodeKind::PopSymbol(local),
            BindingNodeKind::PushScopedSymbol(local),
            BindingNodeKind::PopScopedSymbol(local),
            BindingNodeKind::PushSymbol(shared),
            BindingNodeKind::PopSymbol(shared),
            BindingNodeKind::PushScopedSymbol(shared),
            BindingNodeKind::PopScopedSymbol(shared),
            BindingNodeKind::DropScopes,
            BindingNodeKind::JumpToScope(scope),
            BindingNodeKind::JumpToScope(catalog_only),
            BindingNodeKind::JumpToScope(BindingNodeId::universal_root()),
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            nodes.push((
                self.identities
                    .register_node_for_publication_test(u8::try_from(index + 2).unwrap()),
                kind,
            ));
        }
        self.lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            nodes,
            self.lexical.paths().to_vec(),
            self.lexical.semantics().to_vec(),
            self.lexical.gaps().to_vec(),
        );
        self.rekey_dense()
    }
}

impl LoweredResolutionFactsWithIdentityCatalog {
    /// One lexical-only artifact for a fixture, dense-rekeyed like any other.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_lexical_for_test(
        lexical: LoweredResolutionFragment,
        common: common_fact_lowering::LoweredCommonFacts,
        identities: local_identity::ResolutionIdentityCatalog,
        language: brokk_bifrost_core::analyzer::Language,
    ) -> Self {
        let fragment = lexical.fragment();
        Self {
            lexical,
            typed: LoweredTypedFragment::empty(fragment, language),
            common,
            identities: Box::new(identities),
        }
        .rekey_dense()
    }

    pub(crate) const fn lexical(&self) -> &LoweredResolutionFragment {
        &self.lexical
    }

    pub(crate) const fn typed(&self) -> &LoweredTypedFragment {
        &self.typed
    }

    pub(crate) const fn common(&self) -> &common_fact_lowering::LoweredCommonFacts {
        &self.common
    }

    pub(crate) const fn identities(&self) -> &ResolutionIdentityCatalog {
        &self.identities
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        LoweredResolutionFragment,
        LoweredTypedFragment,
        Box<ResolutionIdentityCatalog>,
    ) {
        (self.lexical, self.typed, self.identities)
    }
}

fn assert_lookup_recipes_reach_emitted_artifact(
    lexical: &LoweredResolutionFragment,
    typed: &LoweredTypedFragment,
    common: &common_fact_lowering::LoweredCommonFacts,
    identities: &ResolutionIdentityCatalog,
) {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    let mut emitted = HashSet::default();
    for (_, path) in lexical.paths() {
        for endpoint in [path.start(), path.end()] {
            emitted.extend(
                endpoint
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol()),
            );
        }
    }
    for gap in lexical.gaps() {
        if let LoweringCoverageFrontier::Candidate {
            lookup: Some(lookup),
            ..
        } = gap.frontier()
        {
            emitted.insert(lookup);
        }
    }
    for route in typed.qualified_routes() {
        emitted.extend([route.lookup(), route.source_lookup()]);
        let member = identities
            .lookup_recipe(route.lookup())
            .expect("member lookup recipe");
        let source = identities
            .lookup_recipe(route.source_lookup())
            .expect("source lookup recipe");
        assert_eq!(member.namespace(), route.namespace());
        assert_eq!(member.semantic_language(), source.semantic_language());
        assert_eq!(member.spelling(), source.spelling());
        assert!(
            source.namespace() == member.namespace()
                || (source.namespace() == ResolutionNamespace::Value
                    && member.namespace() == ResolutionNamespace::Callable),
            "source and member lookup recipes must retain an admitted namespace pair: {source:?}, {member:?}"
        );
    }
    emitted.extend(
        common
            .deferred_member_owners
            .iter()
            .map(|owner| owner.lookup),
    );
    emitted.extend(
        common
            .declared_root_routes
            .iter()
            .map(|route| route.segment),
    );
    emitted.extend(
        common
            .reference_lookup_identities
            .iter()
            .map(|row| row.lookup),
    );
    // The spelled impl-header paths crate derivation walks. A bare `Self`
    // subject has no lexical route, so its lookup is emitted only here.
    for implementation in &common.trait_implementations {
        for path in [&implementation.subject, &implementation.implemented_trait] {
            emitted.extend(path.segments.iter().copied());
            emitted.insert(path.terminal);
        }
    }
    // Protected package stack markers are shared structural identities, not
    // lookup spellings. Their explicit metadata is the only exemption from
    // exact lookup-recipe coverage below.
    let package_domains = common
        .package_references
        .iter()
        .map(|row| row.domain)
        .chain(common.package_members.iter().map(|row| row.domain))
        .collect::<HashSet<_>>();
    for &domain in &package_domains {
        assert!(
            emitted.contains(&domain),
            "package domain must reach an emitted path"
        );
        assert_eq!(
            identities
                .semantic_identity(domain)
                .map(|identity| identity.space()),
            Some(ResolutionSemanticIdentitySpace::Shared)
        );
        assert!(
            identities.lookup_recipe(domain).is_none(),
            "package domains are not lookup spellings"
        );
    }
    let mut emitted_shared = HashSet::default();
    for semantic in emitted {
        let identity = identities
            .semantic_identity(semantic)
            .unwrap_or_else(|| panic!("emitted semantic lacks an identity: {semantic}"));
        if identity.space() == ResolutionSemanticIdentitySpace::Shared
            && !package_domains.contains(&semantic)
        {
            assert!(
                identities.lookup_recipe(semantic).is_some(),
                "emitted Shared semantic lacks a lookup recipe: {semantic}"
            );
            emitted_shared.insert(semantic);
        }
    }
    let registered = identities
        .lookup_recipes()
        .iter()
        .map(|(semantic, _)| *semantic)
        .collect::<HashSet<_>>();
    assert_eq!(
        registered, emitted_shared,
        "lookup recipe catalog must exactly cover every emitted Shared lookup position"
    );
}

fn assert_precedence_namespaces_reach_emitted_artifact(
    lexical: &LoweredResolutionFragment,
    identities: &ResolutionIdentityCatalog,
) {
    let emitted = lexical
        .paths()
        .iter()
        .flat_map(|(_, path)| path.precedence().iter().copied())
        .collect::<HashSet<_>>();
    let registered = identities
        .precedence_namespaces()
        .keys()
        .chain(identities.go_spelling_choices().keys())
        .copied()
        .collect::<HashSet<_>>();
    assert_eq!(
        registered, emitted,
        "precedence namespace catalog must exactly cover every emitted precedence step"
    );
}

/// Lower one blob's facts for preparation.
///
/// What this returns is walked by `resolution_prepare` and then dropped: its
/// rows carry each shared name's interning digest and the single writer turns
/// that into `resolution_identities.id`. So the runtime ids of its shared
/// names never leave it and are numbered per preparation, in the range that
/// says "no store row names this".
pub(crate) fn lower_resolution_facts_with_identity_catalog(
    fragment: BindingFragmentId,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    lower_resolution_facts_for_selection(
        fragment,
        &local_identity::PerRequestSharedNames::new(),
        language,
        facts,
    )
}

/// Lower one blob's facts for the engine.
///
/// The catalog this returns is what a request meets, so its shared names carry
/// the ids the store interned them at and compare with the ids the rows hold.
pub(crate) fn lower_resolution_facts_for_selection(
    fragment: BindingFragmentId,
    names: &dyn local_identity::SharedNameInterner,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
    let lexical = fact_lowering::lower_file_resolution_facts_with_identities(
        &mut identities,
        language,
        facts,
    );
    let typed = typed_fact_lowering::lower_typed_resolution_facts_with_identities(
        &mut identities,
        language,
        facts,
    );
    let common =
        common_fact_lowering::lower_common_resolution_facts(&mut identities, language, facts);
    let identities = identities.finish();
    assert_lookup_recipes_reach_emitted_artifact(&lexical, &typed, &common, &identities);
    assert_precedence_namespaces_reach_emitted_artifact(&lexical, &identities);
    LoweredResolutionFactsWithIdentityCatalog {
        lexical,
        typed,
        common,
        identities: Box::new(identities),
    }
    .rekey_dense()
}

#[cfg(test)]
pub(crate) fn lower_resolution_paths_with_identity_catalog_for_test(
    mut identities: ResolutionIdentityCatalogBuilder,
    language: brokk_bifrost_core::analyzer::Language,
    nodes: Vec<(BindingNodeId, BindingNodeKind)>,
    paths: Vec<(PartialPathId, PartialPath)>,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let fragment = identities.fragment();
    let lexical = LoweredResolutionFragment::new_for_test(fragment, language, nodes, paths);
    let facts = brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts::default();
    let typed = typed_fact_lowering::lower_typed_resolution_facts_with_identities(
        &mut identities,
        language,
        &facts,
    );
    let common =
        common_fact_lowering::lower_common_resolution_facts(&mut identities, language, &facts);
    let identities = identities.finish();
    assert_lookup_recipes_reach_emitted_artifact(&lexical, &typed, &common, &identities);
    assert_precedence_namespaces_reach_emitted_artifact(&lexical, &identities);
    LoweredResolutionFactsWithIdentityCatalog {
        lexical,
        typed,
        common,
        identities: Box::new(identities),
    }
    .rekey_dense()
}

/// Recompute one synthetic site-local typed frontier for private persistence
/// contract tests. Production callers consume the normalized lowered row
/// instead of reconstructing its identity.
#[cfg(any(test, feature = "test-support"))]
pub fn site_type_frontier_semantic_for_test(
    fragment: BindingFragmentId,
    site: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
) -> SemanticId {
    fact_lowering::fixture_names::site_type_frontier_semantic(fragment, site)
}

#[cfg(test)]
pub(crate) use fact_resolution::SelectedContextTestOracle;
