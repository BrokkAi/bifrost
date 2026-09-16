//! Operation-local resolution over caller-supplied immutable fragments.
//!
//! Preload construction preserves normalized evidence and source identities.
//! Point and seeded operations share bounded batch stitching, cycle saturation
//! and precedence selection. This layer does not select a workspace, publish
//! store facts, or activate language resolution.

mod batch;
mod common_fact_lowering;
mod completion_reasons;
mod coverage;
mod engine;
mod fact_lowering;
mod fact_resolution;
mod fact_source;
mod local_identity;
mod model;
mod preloaded_fact_source;
mod saturation;
mod typed_fact_lowering;

fn never_cancelled() -> bool {
    false
}

pub use completion_reasons::CompletionReasons;
pub use model::{
    AlphaRenamingId, BindingFragmentId, BindingNodeId, BindingNodeKind, CompletionReason,
    EndpointSignature, PartialPath, PartialPathId, PartialScopedSymbol, PathCompositionError,
    PrecedenceStep, ResolutionAnswer, ResolutionCompletion, ResolutionIncompleteReason,
    ResolutionSlotValue, ResolutionTypeRef, ResolutionWitness, ScopeStackPattern, SemanticId,
    StackPattern, StackUnificationError, StackVariable, StackVariableId, SymbolStackPattern,
    TypeTransferRule, TypeTransferValueTransform, TypedFrontierState, WitnessStep,
};

pub use batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
    BatchResolutionEngine, BatchResolutionFragmentSource, BatchedReferenceAnswer,
    CandidatePathIdentity, FactReferenceSiteMetadata, MAX_REFERENCE_SEEDS_PER_BATCH,
    ReferenceBatchAnswer, ReferenceSeed, ReferenceSeedBatch, ReferenceSeedReadOutcome,
    ReferenceSeedReadTerminal, ResolutionBatchMetrics, ResolutionBatchSummary,
    ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity, ReverseReferenceSeedRequest,
    SeededPartialPath, SeededReferenceRequest,
};
pub use coverage::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweringCoverageFrontier, LoweringGapOrigin,
};
pub use engine::{
    PreloadedFragment, PreloadedFragmentSource, ReferenceSearchAnswer, ResolutionEngine,
    ResolutionFragmentSource, ResolutionQuery,
};

pub use fact_lowering::{
    FactDefinitionGraphDomain, LoweredResolutionFragment, LoweredSemanticRole, LoweredSemanticSite,
    lower_file_resolution_facts,
};

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
        ResolutionNamespace::Type => kind == ResolutionSiteKind::TypeDeclaration,
        ResolutionNamespace::Value => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::Callable => kind == ResolutionSiteKind::CallableDeclaration,
        ResolutionNamespace::Constructor => kind == ResolutionSiteKind::ConstructorDeclaration,
        ResolutionNamespace::Macro => kind == ResolutionSiteKind::MacroDeclaration,
        ResolutionNamespace::Constant => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::TypeOrValue => false,
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

pub use typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableParameterProperty,
    LoweredCallableSignatureProperty, LoweredConstructionRequirementProperty,
    LoweredDeclarationTypeProperty, LoweredDeclarationVisibilityProperty,
    LoweredDefinitionPropertyGap, LoweredIntrinsicSeed, LoweredMemberOwnerProperty,
    LoweredMemberScopeProperty, LoweredQualifiedSeededRoute, LoweredSupertypeProperty,
    LoweredTypeTransfer, LoweredTypedFragment, LoweredTypedFrontier, lower_typed_resolution_facts,
};

pub use fact_source::{
    FactPageVisitor, FactReadOutcome, FactReadTerminal, FactRequest, FactResolutionSource,
    MAX_FACT_REQUESTS_PER_BATCH, MAX_FACT_ROWS_PER_PAGE, MAX_TYPED_FACT_REQUESTS_PER_BATCH,
    MAX_TYPED_FACT_ROWS_PER_PAGE, QualifiedRouteSlotLookup, SelectedFactRow,
    SelectedGapReasonProvenance, SelectedQualifiedRoute, SelectedTypeFrontierCompletion,
    SelectedTypedFactSource, SelectedTypedRow, TypedFactPageVisitor, TypedFactReadOutcome,
    TypedFactReadTerminal, TypedFactRequest,
};

pub use preloaded_fact_source::PreloadedFactSource;

use crate::hash::HashSet;
use local_identity::ResolutionIdentityCatalogBuilder;
pub(crate) use local_identity::{ResolutionIdentityCatalog, ResolutionSemanticIdentitySpace};
/// One source-lowered resolution artifact and the complete content identity
/// catalog needed to persist its mounted in-memory IDs as local recipes.
#[derive(Debug)]
pub(crate) struct LoweredResolutionFactsWithIdentityCatalog {
    lexical: LoweredResolutionFragment,
    typed: LoweredTypedFragment,
    common: common_fact_lowering::LoweredCommonFacts,
    identities: ResolutionIdentityCatalog,
}

impl LoweredResolutionFactsWithIdentityCatalog {
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
}

fn assert_lookup_recipes_reach_emitted_artifact(
    lexical: &LoweredResolutionFragment,
    typed: &LoweredTypedFragment,
    common: &common_fact_lowering::LoweredCommonFacts,
    identities: &ResolutionIdentityCatalog,
) {
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
    emitted.extend(typed.qualified_routes().iter().map(|route| route.lookup()));
    emitted.extend(
        common
            .declared_root_routes
            .iter()
            .map(|route| route.segment),
    );
    let mut emitted_shared = HashSet::default();
    for semantic in emitted {
        let identity = identities
            .semantic_identity(semantic)
            .unwrap_or_else(|| panic!("emitted semantic lacks an identity: {semantic}"));
        if identity.space() == ResolutionSemanticIdentitySpace::Shared {
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
        .copied()
        .collect::<HashSet<_>>();
    assert_eq!(
        registered, emitted,
        "precedence namespace catalog must exactly cover every emitted precedence step"
    );
}

pub(crate) fn lower_resolution_facts_with_identity_catalog(
    fragment: BindingFragmentId,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment);
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
        identities,
    }
}

#[cfg(test)]
pub(crate) fn normalized_java_bundle_facts_for_test()
-> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts {
    use brokk_bifrost_core::analyzer::resolution_facts::*;
    use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
    // Synthetic normalized input: this is not a Java parser or resolver oracle.
    let scope = |id, parent: Option<u32>, owner: Option<u32>, kind, start_byte, end_byte| {
        ResolutionScopeFact {
            id: ResolutionScopeId::new(id),
            parent: parent.map(ResolutionScopeId::new),
            owner: owner.map(ResolutionSiteId::new),
            kind,
            start_byte,
            end_byte,
        }
    };
    let site = |id, scope, kind, start_byte| ResolutionSiteFact {
        id: ResolutionSiteId::new(id),
        scope: ResolutionScopeId::new(scope),
        kind,
        start_byte,
        end_byte: start_byte + 1,
    };
    let identifier = |site, name, role, namespace| PositionedIdentifierFact {
        site: ResolutionSiteId::new(site),
        name: ResolutionNameId::new(name),
        role,
        namespace,
        qualifier: None,
    };
    let binder =
        |site, scope, kind, hoisting, activation_start, activation_end| ResolutionBinderFact {
            declaration: ResolutionSiteId::new(site),
            scope: ResolutionScopeId::new(scope),
            kind,
            hoisting,
            activation_start,
            activation_end,
        };
    FileResolutionFacts {
        names: ["acme", "Outer", "run", "value"]
            .into_iter()
            .enumerate()
            .map(|(id, spelling)| ResolutionNameFact {
                id: ResolutionNameId::try_from_index(id).unwrap(),
                spelling: spelling.into(),
            })
            .collect(),
        scopes: vec![
            scope(0, None, None, ResolutionScopeKind::CompilationUnit, 0, 200),
            scope(1, Some(0), Some(1), ResolutionScopeKind::TypeBody, 10, 190),
            scope(
                2,
                Some(1),
                Some(2),
                ResolutionScopeKind::Executable,
                30,
                180,
            ),
        ],
        sites: vec![
            site(0, 0, ResolutionSiteKind::PackageDeclaration, 1),
            site(1, 0, ResolutionSiteKind::TypeDeclaration, 10),
            site(2, 1, ResolutionSiteKind::CallableDeclaration, 20),
            site(3, 2, ResolutionSiteKind::ValueDeclaration, 31),
            site(4, 2, ResolutionSiteKind::ValueDeclaration, 70),
            site(5, 2, ResolutionSiteKind::ValueReference, 50),
            site(6, 2, ResolutionSiteKind::ValueReference, 90),
        ],
        identifiers: vec![
            identifier(
                1,
                1,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            identifier(
                2,
                2,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Callable,
            ),
            identifier(
                3,
                3,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            ),
            identifier(
                4,
                3,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            ),
            identifier(
                5,
                3,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            ),
            identifier(
                6,
                3,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            ),
        ],
        binders: vec![
            binder(
                1,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                200,
            ),
            binder(
                2,
                1,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                10,
                190,
            ),
            binder(
                3,
                2,
                ResolutionBinderKind::Parameter,
                HoistingClass::ScopeWide,
                30,
                180,
            ),
            binder(
                4,
                2,
                ResolutionBinderKind::Local,
                HoistingClass::SourceOrder,
                71,
                180,
            ),
        ],
        packages: vec![ResolutionPackageFact {
            root_scope: ResolutionScopeId::new(0),
            declaration: Some(ResolutionSiteId::new(0)),
            placement_gap_site: ResolutionSiteId::new(0),
        }],
        package_segments: vec![ResolutionPackageSegmentFact {
            root_scope: ResolutionScopeId::new(0),
            ordinal: 0,
            name: ResolutionNameId::new(0),
        }],
        root_exports: vec![ResolutionRootExportFact {
            root_scope: ResolutionScopeId::new(0),
            declaration: ResolutionSiteId::new(1),
            namespace: ResolutionNamespace::Type,
        }],
        type_slots: vec![
            ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(3),
                role: ResolutionTypeSlotRole::DeclaredValue,
            },
            ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(1),
                site: ResolutionSiteId::new(4),
                role: ResolutionTypeSlotRole::DeclaredValue,
            },
            ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(2),
                site: ResolutionSiteId::new(4),
                role: ResolutionTypeSlotRole::AssignmentValue,
            },
        ],
        declaration_type_slots: vec![
            DeclarationTypeSlotFact {
                declaration: ResolutionSiteId::new(3),
                slot: ResolutionTypeSlotId::new(0),
                role: DeclarationTypeRole::Parameter,
            },
            DeclarationTypeSlotFact {
                declaration: ResolutionSiteId::new(4),
                slot: ResolutionTypeSlotId::new(1),
                role: DeclarationTypeRole::Value,
            },
        ],
        type_transfers: vec![ResolutionTypeTransferFact {
            input: ResolutionTypeSlotId::new(0),
            output: ResolutionTypeSlotId::new(2),
            kind: ResolutionTypeTransferKind::Assignment,
            indirection_delta: 0,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        }],
        visibility_eligibilities: vec![ResolutionVisibilityEligibilityFact {
            declaration: ResolutionSiteId::new(1),
        }],
        declaration_visibilities: vec![ResolutionDeclarationVisibilityFact {
            declaration: ResolutionSiteId::new(1),
            visibility: DeclaredVisibility::Public,
        }],
        callable_signatures: vec![ResolutionCallableSignatureFact {
            callable: ResolutionSiteId::new(2),
            type_parameter_count: 0,
        }],
        callable_parameters: vec![ResolutionCallableParameterFact {
            callable: ResolutionSiteId::new(2),
            ordinal: 0,
            parameter: ResolutionSiteId::new(3),
            value_type: ResolutionTypeSlotId::new(0),
            repeated: false,
        }],
        ..FileResolutionFacts::default()
    }
}

pub use fact_resolution::{
    FactCallableReceiverChannels, FactCallableReceiverDisposition,
    FactCallableReceiverTargetDisposition, FactProjectedFrontier, FactReadSession,
    FactReferenceReceiverGap, FactResolutionAnswer,
};
