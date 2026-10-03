//! Consuming remount of one fully lowered resolution artifact.
//!
//! A lowered artifact uses opaque runtime IDs mounted under one binding
//! fragment. Its identity catalog retains the producer-stable local
//! descriptors needed to mount the same content under another fragment. This
//! module performs that translation without reading source facts again.

use std::collections::BTreeSet;

use crate::CancellationToken;

use super::LoweredResolutionFactsWithIdentityCatalog;
use super::batch::FactReferenceSiteMetadata;
use super::common_fact_lowering::{
    LoweredAdditionalDefinitionNamespace, LoweredCommonFacts, LoweredDeclaredRootRoute,
    LoweredDeclaredTypeRelation, LoweredDeferredMemberOwner, LoweredDefinitionUnitCrosswalk,
    LoweredImplHeaderPath, LoweredReferenceLookupIdentity, LoweredRelationMember,
    LoweredRootImportProvenance, LoweredTraitImplementation,
};
use super::fact_lowering::{
    LoweredCoverageGap, LoweredResolutionFragment, LoweredSemanticSite, LoweringCoverageFrontier,
};
use super::local_identity::{ResolutionIdentityTranslation, ResolutionMountTranslation};
use super::model::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, EndpointSignature, PartialPath,
    PartialPathId, PartialScopedSymbol, PrecedenceStep, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionSlotValue, ResolutionTypeRef, ScopeStackPattern,
    SemanticId, StackPattern, StackVariableId, SymbolStackPattern, TypeTransferRule,
    TypedFrontierState, WitnessStep,
};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableParameterProperty,
    LoweredCallableResultTypeProperty, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredQualifiedSeededRoute,
    LoweredSupertypeProperty, LoweredTypeComponent, LoweredTypeTransfer, LoweredTypedFragment,
    LoweredTypedFrontier, LoweredUnderlyingType,
};

/// **Every collection keyed or ordered by a mounted id is rebuilt here, never
/// rewritten in place.** A translation changes what a mounted id *is*, so a
/// map keyed by one, a set of them, or a vector sorted by one is not a
/// container whose elements can be replaced: its shape depends on the values
/// it holds. `remount_lexical`, `remount_typed` and `remount_common` below
/// therefore allocate a fresh collection and push translated values into it,
/// and a reviewer adding a case to any of them has to do the same.
///
/// The rule the same translation rests on is the one stage 1a's ordering bug
/// taught (lane document section 18e): **a catalog position is a persisted
/// local key, so whatever orders a catalog orders by content and never by an
/// id.** `ResolutionIdentityCatalogBuilder::finish` holds that end of it, and
/// `a_catalog_position_does_not_depend_on_an_interned_id` is the pin.
impl LoweredResolutionFactsWithIdentityCatalog {
    pub(super) fn rekey_dense(self) -> Self {
        let fragment = self.lexical.fragment();
        let Self {
            lexical,
            typed,
            common,
            identities,
        } = self;
        let (identities, translation) = (*identities).rekey_dense();
        let cancellation = CancellationToken::default();
        let lexical = remount_lexical(lexical, fragment, &translation, &cancellation)
            .expect("dense resolution rekeying cannot be cancelled");
        let typed = remount_typed(typed, fragment, &translation, &cancellation)
            .expect("dense resolution rekeying cannot be cancelled");
        let common = remount_common(common, &translation, &cancellation)
            .expect("dense resolution rekeying cannot be cancelled");
        Self {
            lexical,
            typed,
            common,
            identities: Box::new(identities),
        }
    }

    pub(crate) fn instantiate_macro_input(
        mut self,
        invocation_digest: [u8; 32],
        checkpoint: super::local_identity::ResolutionNodeIdentity,
        module_scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let fragment = self.lexical.fragment();
        self.identities
            .specialize_macro_input(invocation_digest, checkpoint, module_scope);
        let mut artifact = self.remount(fragment, cancellation)?;
        let module = artifact.identities.register_macro_module_node(module_scope);
        artifact.lexical.attach_macro_module_witnesses(
            &super::selected_context::CatalogRootImportAnchors::new(&artifact.identities),
            module,
        )?;
        Some(artifact)
    }

    /// This artifact with every runtime id replaced by the one an operation
    /// assigned it, and its catalog with it.
    ///
    /// A macro capsule's ids are its own catalog's positions, which collide
    /// with the host blob's; the operation gives each identity a key and this
    /// moves the artifact onto them. It is the same walk a remount does, with
    /// the translation supplied rather than derived from a catalog.
    pub(crate) fn retargeted(
        self,
        assigned: &super::local_identity::ResolutionRegisteredIdentities,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let Self {
            lexical,
            typed,
            common,
            identities,
        } = self;
        let fragment = lexical.fragment();
        let lexical = remount_lexical(lexical, fragment, assigned, cancellation)?;
        let typed = remount_typed(typed, fragment, assigned, cancellation)?;
        let common = remount_common(common, assigned, cancellation)?;
        Some(Self {
            lexical,
            typed,
            common,
            identities: Box::new(identities.retargeted(assigned)),
        })
    }

    pub(crate) fn remount(
        self,
        fragment: BindingFragmentId,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        if cancellation.is_cancelled() {
            return None;
        }
        let Self {
            lexical,
            typed,
            common,
            identities,
        } = self;
        let (identities, translation) = (*identities).remount(fragment, cancellation)?;
        let lexical = remount_lexical(lexical, fragment, &translation, cancellation)?;
        let typed = remount_typed(typed, fragment, &translation, cancellation)?;
        let common = remount_common(common, &translation, cancellation)?;
        if cancellation.is_cancelled() {
            return None;
        }
        super::assert_lookup_recipes_reach_emitted_artifact(&lexical, &typed, &common, &identities);
        super::assert_precedence_namespaces_reach_emitted_artifact(&lexical, &identities);
        Some(Self {
            lexical,
            typed,
            common,
            identities: Box::new(identities),
        })
    }
}

/// One lexical half moved onto the ids an operation assigned it. See
/// [`LoweredResolutionFactsWithIdentityCatalog::retargeted`].
pub(crate) fn retarget_lexical(
    lexical: LoweredResolutionFragment,
    assigned: &super::local_identity::ResolutionRegisteredIdentities,
    cancellation: &CancellationToken,
) -> Option<LoweredResolutionFragment> {
    let fragment = lexical.fragment();
    remount_lexical(lexical, fragment, assigned, cancellation)
}

fn remount_lexical(
    lexical: LoweredResolutionFragment,
    fragment: BindingFragmentId,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredResolutionFragment> {
    let mut nodes = Vec::with_capacity(lexical.nodes().len());
    for &(id, kind) in lexical.nodes() {
        if cancellation.is_cancelled() {
            return None;
        }
        nodes.push((translation.node(id), remount_node_kind(kind, translation)));
    }
    let mut paths = Vec::with_capacity(lexical.paths().len());
    for (id, path) in lexical.paths() {
        if cancellation.is_cancelled() {
            return None;
        }
        paths.push((
            translation.path(*id),
            remount_path(path, translation, cancellation)?,
        ));
    }
    let mut semantics = Vec::with_capacity(lexical.semantics().len());
    for &site in lexical.semantics() {
        if cancellation.is_cancelled() {
            return None;
        }
        semantics.push(
            LoweredSemanticSite::new(
                site.site(),
                site.namespace(),
                site.role(),
                translation.semantic(site.semantic()),
                translation.node(site.node()),
                site.site_metadata()
                    .map(|metadata| remount_site_metadata(metadata, translation)),
            )
            .with_go_definition_namespaces(site.go_definition_namespaces()),
        );
    }
    let mut gaps = Vec::with_capacity(lexical.gaps().len());
    for gap in lexical.gaps() {
        if cancellation.is_cancelled() {
            return None;
        }
        gaps.push(LoweredCoverageGap::new(
            gap.digest(),
            translation.semantic(gap.reason_semantic()),
            gap.site(),
            gap.origin(),
            remount_coverage_frontier(gap.frontier(), translation),
        ));
    }
    let remounted =
        LoweredResolutionFragment::new(fragment, lexical.language(), nodes, paths, semantics, gaps);
    #[cfg(any(test, feature = "test-support"))]
    let remounted = {
        let mut terminals = Vec::with_capacity(lexical.hierarchy_terminals().len());
        for &(reason, node) in lexical.hierarchy_terminals() {
            if cancellation.is_cancelled() {
                return None;
            }
            terminals.push((translation.semantic(reason), translation.node(node)));
        }
        remounted.with_hierarchy_terminals(terminals)
    };
    Some(remounted)
}

fn remount_node_kind(
    kind: BindingNodeKind,
    translation: &impl ResolutionIdentityTranslation,
) -> BindingNodeKind {
    match kind {
        BindingNodeKind::Root => BindingNodeKind::Root,
        BindingNodeKind::Scope => BindingNodeKind::Scope,
        BindingNodeKind::PushSymbol(semantic) => {
            BindingNodeKind::PushSymbol(translation.semantic(semantic))
        }
        BindingNodeKind::PopSymbol(semantic) => {
            BindingNodeKind::PopSymbol(translation.semantic(semantic))
        }
        BindingNodeKind::PushScopedSymbol(semantic) => {
            BindingNodeKind::PushScopedSymbol(translation.semantic(semantic))
        }
        BindingNodeKind::PopScopedSymbol(semantic) => {
            BindingNodeKind::PopScopedSymbol(translation.semantic(semantic))
        }
        BindingNodeKind::DropScopes => BindingNodeKind::DropScopes,
        BindingNodeKind::JumpToScope(node) => BindingNodeKind::JumpToScope(translation.node(node)),
        BindingNodeKind::Reference(semantic) => {
            BindingNodeKind::Reference(translation.semantic(semantic))
        }
        BindingNodeKind::Definition(semantic) => {
            BindingNodeKind::Definition(translation.semantic(semantic))
        }
    }
}

pub(super) fn remount_path(
    path: &PartialPath,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<PartialPath> {
    let start = remount_endpoint(path.start(), translation, cancellation)?;
    let end = remount_endpoint(path.end(), translation, cancellation)?;
    let mut precedence = Vec::with_capacity(path.precedence().len());
    for &step in path.precedence() {
        if cancellation.is_cancelled() {
            return None;
        }
        precedence.push(PrecedenceStep {
            semantic: translation.semantic(step.semantic),
            ..step
        });
    }
    let mut witness = Vec::with_capacity(path.witness().len());
    for &step in path.witness() {
        if cancellation.is_cancelled() {
            return None;
        }
        witness.push(match step {
            WitnessStep::Node(node) => WitnessStep::Node(translation.node(node)),
            WitnessStep::Candidate { semantic, outcome } => WitnessStep::Candidate {
                semantic: translation.semantic(semantic),
                outcome,
            },
            WitnessStep::Boundary { semantic, status } => WitnessStep::Boundary {
                semantic: translation.semantic(semantic),
                status,
            },
        });
    }
    let completion = remount_completion(path.completion(), translation, cancellation)?;
    PartialPath::new_with_poll(
        start,
        end,
        precedence.into_boxed_slice(),
        witness.into_boxed_slice(),
        completion,
        &mut || cancellation.is_cancelled(),
    )
}

pub(super) fn remount_endpoint(
    endpoint: &EndpointSignature,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<EndpointSignature> {
    Some(EndpointSignature::new_scoped(
        translation.node(endpoint.node()),
        remount_symbol_stack(endpoint.symbols(), translation, cancellation)?,
        remount_scope_stack(endpoint.scopes(), translation, cancellation)?,
    ))
}

fn remount_symbol_stack(
    stack: &SymbolStackPattern,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<SymbolStackPattern> {
    let mut fixed = Vec::with_capacity(stack.fixed().len());
    for symbol in stack.fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        fixed.push(match symbol.scopes() {
            Some(scopes) => PartialScopedSymbol::scoped(
                translation.semantic(symbol.symbol()),
                remount_scope_stack(scopes, translation, cancellation)?,
            ),
            None => PartialScopedSymbol::unscoped(translation.semantic(symbol.symbol())),
        });
    }
    Some(StackPattern::new(
        fixed,
        stack.tail().map(|tail| translation.stack_variable(tail)),
    ))
}

fn remount_scope_stack(
    stack: &ScopeStackPattern,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<ScopeStackPattern> {
    let mut fixed = Vec::with_capacity(stack.fixed().len());
    for &node in stack.fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        fixed.push(translation.node(node));
    }
    Some(StackPattern::new(
        fixed,
        stack.tail().map(|tail| translation.stack_variable(tail)),
    ))
}

pub(super) fn remount_completion(
    completion: &ResolutionCompletion,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<ResolutionCompletion> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return (!cancellation.is_cancelled()).then_some(ResolutionCompletion::Complete);
    };
    let mut remounted = BTreeSet::new();
    for reason in reasons.iter() {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted.insert(match reason {
            ResolutionIncompleteReason::Cancelled => ResolutionIncompleteReason::Cancelled,
            // Three reasons no producer publishes: the scheduler mints the
            // cyclic prefix dependencies while they run, the reverse row
            // reader mints receiver and time budget stops after resolution has
            // answered, and the crate route mints unmounted file routes from
            // one selection's live crate rows. A remount rejects them and a
            // mount splice translates them; the translation says which.
            reason @ (ResolutionIncompleteReason::CyclicPrefixDependency(_)
            | ResolutionIncompleteReason::ReceiverBudgetExhausted(_)
            | ResolutionIncompleteReason::TimeBudgetExceeded(_)
            | ResolutionIncompleteReason::UnmountedFile { .. }) => {
                translation.operation_local_reason(reason)
            }
            ResolutionIncompleteReason::CyclicExpansion(path) => {
                ResolutionIncompleteReason::CyclicExpansion(translation.path(*path))
            }
            ResolutionIncompleteReason::InconsistentPrecedence(semantic) => {
                ResolutionIncompleteReason::InconsistentPrecedence(translation.semantic(*semantic))
            }
            ResolutionIncompleteReason::OpenBoundary { semantic, status } => {
                ResolutionIncompleteReason::OpenBoundary {
                    semantic: translation.semantic(*semantic),
                    status: *status,
                }
            }
            ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                ResolutionIncompleteReason::UnsupportedSemantic(translation.semantic(*semantic))
            }
        });
    }
    ResolutionCompletion::from_canonical_reasons(
        remounted.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        || cancellation.is_cancelled(),
    )
}

pub(super) fn remount_site_metadata(
    metadata: FactReferenceSiteMetadata,
    translation: &impl ResolutionIdentityTranslation,
) -> FactReferenceSiteMetadata {
    FactReferenceSiteMetadata::new(
        metadata.site(),
        metadata.namespace(),
        metadata.site_kind(),
        metadata.start_byte(),
        metadata.end_byte(),
        metadata.unqualified(),
        metadata
            .reference_owner()
            .map(|owner| owner.map(|semantic| translation.semantic(semantic))),
        metadata.callable_receiver_origin(),
    )
    .with_go_spelling_namespace(metadata.go_spelling_namespace())
    .with_go_package_qualifier(metadata.go_package_qualifier())
}

fn remount_coverage_frontier(
    frontier: LoweringCoverageFrontier,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweringCoverageFrontier {
    match frontier {
        LoweringCoverageFrontier::Fragment => LoweringCoverageFrontier::Fragment,
        LoweringCoverageFrontier::Enumeration => LoweringCoverageFrontier::Enumeration,
        LoweringCoverageFrontier::CandidateInventory { direction } => {
            LoweringCoverageFrontier::CandidateInventory { direction }
        }
        LoweringCoverageFrontier::Reference { semantic, node } => {
            LoweringCoverageFrontier::Reference {
                semantic: translation.semantic(semantic),
                node: translation.node(node),
            }
        }
        LoweringCoverageFrontier::Candidate {
            direction,
            endpoint,
            lookup,
        } => LoweringCoverageFrontier::Candidate {
            direction,
            endpoint: translation.node(endpoint),
            lookup: lookup.map(|semantic| translation.semantic(semantic)),
        },
        LoweringCoverageFrontier::Type { frontier } => LoweringCoverageFrontier::Type {
            frontier: translation.semantic(frontier),
        },
    }
}

fn remount_typed(
    typed: LoweredTypedFragment,
    fragment: BindingFragmentId,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredTypedFragment> {
    let mut frontiers = Vec::with_capacity(typed.frontiers().len());
    for frontier in typed.frontiers() {
        if cancellation.is_cancelled() {
            return None;
        }
        frontiers.push(remount_typed_frontier(frontier, translation));
    }
    let mut transfers = Vec::with_capacity(typed.transfers().len());
    for transfer in typed.transfers() {
        if cancellation.is_cancelled() {
            return None;
        }
        transfers.push(remount_transfer(transfer, translation, cancellation)?);
    }
    let type_components = typed
        .type_components()
        .iter()
        .map(|component| {
            LoweredTypeComponent::new(
                translation.semantic(component.container()),
                component.constructor(),
                component.kind(),
                translation.semantic(component.component()),
            )
        })
        .collect();
    let underlying_types = typed
        .underlying_types()
        .iter()
        .map(|underlying| {
            LoweredUnderlyingType::new(
                translation.semantic(underlying.definition()),
                translation.semantic(underlying.slot()),
            )
        })
        .collect();
    let mut intrinsic_seeds = Vec::with_capacity(typed.intrinsic_seeds().len());
    for seed in typed.intrinsic_seeds() {
        if cancellation.is_cancelled() {
            return None;
        }
        intrinsic_seeds.push(remount_intrinsic_seed(seed, translation, cancellation)?);
    }
    let mut projections = Vec::with_capacity(typed.projections().len());
    for projection in typed.projections() {
        if cancellation.is_cancelled() {
            return None;
        }
        projections.push(remount_binding_projection(projection, translation));
    }
    let mut qualified_routes = Vec::with_capacity(typed.qualified_routes().len());
    for route in typed.qualified_routes() {
        if cancellation.is_cancelled() {
            return None;
        }
        qualified_routes.push(LoweredQualifiedSeededRoute::new_with_source_lookup(
            translation.semantic(route.reference()),
            translation.semantic(route.qualifier_slot()),
            translation.semantic(route.lookup()),
            route.namespace(),
            translation.semantic(route.source_lookup()),
            route.precedence_ordinal(),
            translation.semantic(route.projection_output_slot()),
            route.projection_kind(),
            translation.semantic(route.coarse_gap_reason()),
            route.open_member_surface(),
        ));
    }
    let mut declaration_types = Vec::with_capacity(typed.declaration_types().len());
    for property in typed.declaration_types() {
        if cancellation.is_cancelled() {
            return None;
        }
        declaration_types.push(remount_declaration_type(property, translation));
    }
    let mut declaration_visibilities = Vec::with_capacity(typed.declaration_visibilities().len());
    for property in typed.declaration_visibilities() {
        if cancellation.is_cancelled() {
            return None;
        }
        declaration_visibilities.push(remount_declaration_visibility(property, translation));
    }
    let mut member_scopes = Vec::with_capacity(typed.member_scopes().len());
    for property in typed.member_scopes() {
        if cancellation.is_cancelled() {
            return None;
        }
        member_scopes.push(remount_member_scope(property, translation));
    }
    let mut member_owners = Vec::with_capacity(typed.member_owners().len());
    for property in typed.member_owners() {
        if cancellation.is_cancelled() {
            return None;
        }
        member_owners.push(remount_member_owner(property, translation));
    }
    let mut deferred_member_owners = Vec::with_capacity(typed.deferred_member_owners().len());
    for property in typed.deferred_member_owners() {
        if cancellation.is_cancelled() {
            return None;
        }
        deferred_member_owners.push(remount_deferred_member_owner(*property, translation));
    }
    let mut construction_requirements = Vec::with_capacity(typed.construction_requirements().len());
    for property in typed.construction_requirements() {
        if cancellation.is_cancelled() {
            return None;
        }
        construction_requirements.push(remount_construction_requirement(property, translation));
    }
    let mut supertypes = Vec::with_capacity(typed.supertypes().len());
    for property in typed.supertypes() {
        if cancellation.is_cancelled() {
            return None;
        }
        supertypes.push(remount_supertype(property, translation));
    }
    let mut property_gaps = Vec::with_capacity(typed.property_gaps().len());
    for gap in typed.property_gaps() {
        if cancellation.is_cancelled() {
            return None;
        }
        property_gaps.push(remount_definition_property_gap(gap, translation));
    }
    let mut call_obligations = Vec::with_capacity(typed.call_obligations().len());
    for obligation in typed.call_obligations() {
        if cancellation.is_cancelled() {
            return None;
        }
        call_obligations.push(remount_call_obligation(
            obligation,
            translation,
            cancellation,
        )?);
    }
    let mut callable_signatures = Vec::with_capacity(typed.callable_signatures().len());
    for signature in typed.callable_signatures() {
        if cancellation.is_cancelled() {
            return None;
        }
        callable_signatures.push(remount_callable_signature(
            signature,
            translation,
            cancellation,
        )?);
    }

    if cancellation.is_cancelled() {
        return None;
    }
    Some(LoweredTypedFragment::new_with_type_relations(
        fragment,
        typed.language(),
        frontiers,
        transfers,
        type_components,
        underlying_types,
        intrinsic_seeds,
        projections,
        qualified_routes,
        declaration_types,
        declaration_visibilities,
        member_scopes,
        member_owners,
        deferred_member_owners,
        construction_requirements,
        supertypes,
        property_gaps,
        call_obligations,
        callable_signatures,
    ))
}

pub(super) fn remount_transfer(
    transfer: &LoweredTypeTransfer,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredTypeTransfer> {
    Some(LoweredTypeTransfer::new(
        translation.semantic(transfer.source_slot()),
        transfer.kind(),
        remount_type_transfer_rule(transfer.rule(), translation, cancellation)?,
    ))
}

pub(super) fn remount_frontier_state(
    frontier: &TypedFrontierState,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<TypedFrontierState> {
    let mut possible_values = Vec::with_capacity(frontier.possible_values().len());
    for &value in frontier.possible_values() {
        if cancellation.is_cancelled() {
            return None;
        }
        possible_values.push(remount_slot_value(value, translation));
    }
    Some(TypedFrontierState::new(
        translation.semantic(frontier.slot()),
        possible_values,
        remount_completion(frontier.completion(), translation, cancellation)?,
    ))
}

fn remount_slot_value(
    value: ResolutionSlotValue,
    translation: &impl ResolutionIdentityTranslation,
) -> ResolutionSlotValue {
    let remount_type = |ty: ResolutionTypeRef| {
        ResolutionTypeRef::new_with_reference_indirection(
            translation.semantic(ty.identity()),
            ty.indirection(),
            ty.reference_indirection(),
        )
    };
    match value {
        ResolutionSlotValue::TypeObject(ty) => ResolutionSlotValue::type_object(remount_type(ty)),
        ResolutionSlotValue::Runtime { ty, addressable } => {
            ResolutionSlotValue::runtime(remount_type(ty), addressable)
        }
    }
}

pub(super) fn remount_deferred_member_owner(
    property: LoweredDeferredMemberOwner,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredDeferredMemberOwner {
    LoweredDeferredMemberOwner::new(
        translation.semantic(property.definition()),
        translation.semantic(property.owner_frontier()),
        translation.semantic(property.lookup()),
        property.kind(),
        property.access(),
        property.qualifier_compatibility(),
    )
    .with_hierarchy_frontier(
        property
            .hierarchy_frontier()
            .map(|frontier| translation.semantic(frontier)),
    )
}

fn remount_impl_header_path(
    path: LoweredImplHeaderPath,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredImplHeaderPath {
    LoweredImplHeaderPath {
        segments: path
            .segments
            .into_iter()
            .map(|segment| translation.semantic(segment))
            .collect(),
        terminal: translation.semantic(path.terminal),
    }
}

fn remount_common(
    common: LoweredCommonFacts,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredCommonFacts> {
    let LoweredCommonFacts {
        additional_definition_namespaces,
        definition_unit_crosswalks,
        deferred_member_owners,
        declared_type_relations,
        relation_members,
        declared_root_routes,
        root_import_provenance,
        package_references,
        package_members,
        go_package_imports,
        reference_lookup_identities,
        trait_implementations,
    } = common;

    let mut remounted_additional = Vec::with_capacity(additional_definition_namespaces.len());
    for row in additional_definition_namespaces {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_additional.push(LoweredAdditionalDefinitionNamespace {
            definition: translation.semantic(row.definition),
            namespace: row.namespace,
            hoisting: row.hoisting,
        });
    }
    let mut remounted_crosswalks = Vec::with_capacity(definition_unit_crosswalks.len());
    for row in definition_unit_crosswalks {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_crosswalks.push(LoweredDefinitionUnitCrosswalk {
            definition: translation.semantic(row.definition),
            unit: row.unit,
        });
    }
    let mut remounted_deferred = Vec::with_capacity(deferred_member_owners.len());
    for row in deferred_member_owners {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_deferred.push(remount_deferred_member_owner(row, translation));
    }
    let mut remounted_relations = Vec::with_capacity(declared_type_relations.len());
    for row in declared_type_relations {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_relations.push(LoweredDeclaredTypeRelation {
            relation: translation.semantic(row.relation),
            subject_frontier: translation.semantic(row.subject_frontier),
            kind: row.kind,
            target_reference: row
                .target_reference
                .map(|semantic| translation.semantic(semantic)),
            target_frontier: row
                .target_frontier
                .map(|semantic| translation.semantic(semantic)),
        });
    }
    let mut remounted_members = Vec::with_capacity(relation_members.len());
    for row in relation_members {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_members.push(LoweredRelationMember {
            relation: translation.semantic(row.relation),
            position: row.position,
            definition: translation.semantic(row.definition),
            kind: row.kind,
        });
    }
    let mut remounted_routes = Vec::with_capacity(declared_root_routes.len());
    for row in declared_root_routes {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_routes.push(LoweredDeclaredRootRoute {
            root_scope: translation.node(row.root_scope),
            position: row.position,
            segment: translation.semantic(row.segment),
        });
    }
    let mut remounted_import_provenance = Vec::with_capacity(root_import_provenance.len());
    for row in root_import_provenance {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_import_provenance.push(LoweredRootImportProvenance {
            token: translation.semantic(row.token),
            ..row
        });
    }
    let mut remounted_package_references = Vec::with_capacity(package_references.len());
    for row in package_references {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_package_references.push(super::fact_lowering::package::LoweredPackageReference {
            token: translation.semantic(row.token),
            domain: translation.semantic(row.domain),
            reference: translation.semantic(row.reference),
            root_scope: translation.node(row.root_scope),
            lookup: translation.semantic(row.lookup),
            ..row
        });
    }
    let mut remounted_package_members = Vec::with_capacity(package_members.len());
    for row in package_members {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_package_members.push(super::fact_lowering::package::LoweredPackageMember {
            token: translation.semantic(row.token),
            domain: translation.semantic(row.domain),
            definition: translation.semantic(row.definition),
            root_scope: translation.node(row.root_scope),
            lookup: translation.semantic(row.lookup),
            ..row
        });
    }
    let mut remounted_go_package_imports = Vec::with_capacity(go_package_imports.len());
    for row in go_package_imports {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_go_package_imports.push(super::fact_lowering::package::LoweredGoPackageImport {
            definition: translation.semantic(row.definition),
            file_scope: translation.node(row.file_scope),
            spelling_choice: translation.semantic(row.spelling_choice),
            ..row
        });
    }
    let mut remounted_reference_lookup_identities =
        Vec::with_capacity(reference_lookup_identities.len());
    for row in reference_lookup_identities {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_reference_lookup_identities.push(LoweredReferenceLookupIdentity {
            reference: translation.semantic(row.reference),
            lookup: translation.semantic(row.lookup),
        });
    }
    let mut remounted_trait_implementations = Vec::with_capacity(trait_implementations.len());
    for row in trait_implementations {
        if cancellation.is_cancelled() {
            return None;
        }
        remounted_trait_implementations.push(LoweredTraitImplementation {
            relation: translation.semantic(row.relation),
            subject: remount_impl_header_path(row.subject, translation),
            implemented_trait: remount_impl_header_path(row.implemented_trait, translation),
            impl_site: row.impl_site,
            impl_start_byte: row.impl_start_byte,
            impl_end_byte: row.impl_end_byte,
        });
    }
    if cancellation.is_cancelled() {
        return None;
    }
    Some(LoweredCommonFacts::new(
        remounted_additional,
        remounted_crosswalks,
        remounted_deferred,
        remounted_relations,
        remounted_members,
        remounted_routes,
        remounted_import_provenance,
        remounted_package_references,
        remounted_package_members,
        remounted_go_package_imports,
        remounted_reference_lookup_identities,
        remounted_trait_implementations,
    ))
}

pub(super) fn remount_typed_frontier(
    frontier: &LoweredTypedFrontier,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredTypedFrontier {
    let mut remounted =
        LoweredTypedFrontier::new(translation.semantic(frontier.slot()), frontier.role());
    if let Some((reference, node)) = frontier.type_identity_reference() {
        remounted = remounted
            .with_type_identity_reference(translation.semantic(reference), translation.node(node));
    }
    remounted
}

pub(super) fn remount_intrinsic_seed(
    seed: &LoweredIntrinsicSeed,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredIntrinsicSeed> {
    Some(LoweredIntrinsicSeed::new(
        seed.kind(),
        seed.spelling().to_owned(),
        remount_frontier_state(seed.frontier(), translation, cancellation)?,
    ))
}

pub(super) fn remount_binding_projection(
    projection: &LoweredBindingProjection,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredBindingProjection {
    LoweredBindingProjection::new(
        translation.semantic(projection.reference()),
        translation.semantic(projection.output_slot()),
        projection.kind(),
    )
}

pub(super) fn remount_declaration_type(
    property: &LoweredDeclarationTypeProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredDeclarationTypeProperty {
    LoweredDeclarationTypeProperty::new(
        translation.semantic(property.definition()),
        translation.semantic(property.slot()),
        property.role(),
    )
}

pub(super) fn remount_declaration_visibility(
    property: &LoweredDeclarationVisibilityProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredDeclarationVisibilityProperty {
    LoweredDeclarationVisibilityProperty::new(
        translation.semantic(property.definition()),
        property.visibility(),
    )
}

pub(super) fn remount_member_scope(
    property: &LoweredMemberScopeProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredMemberScopeProperty {
    LoweredMemberScopeProperty::new(
        translation.semantic(property.definition()),
        translation.node(property.scope_head()),
    )
}

pub(super) fn remount_member_owner(
    property: &LoweredMemberOwnerProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredMemberOwnerProperty {
    LoweredMemberOwnerProperty::new(
        translation.semantic(property.definition()),
        translation.semantic(property.owner_definition()),
        translation.node(property.owner_scope_head()),
        property.kind(),
        property.access(),
        property.qualifier_compatibility(),
    )
}

pub(super) fn remount_construction_requirement(
    property: &LoweredConstructionRequirementProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredConstructionRequirementProperty {
    LoweredConstructionRequirementProperty::new(
        translation.semantic(property.definition()),
        translation.semantic(property.required_owner_definition()),
        property.kind(),
    )
}

pub(super) fn remount_supertype(
    property: &LoweredSupertypeProperty,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredSupertypeProperty {
    LoweredSupertypeProperty::new(
        translation.semantic(property.definition()),
        translation.semantic(property.reference()),
        translation.semantic(property.frontier()),
        property.kind(),
    )
}

pub(super) fn remount_definition_property_gap(
    gap: &LoweredDefinitionPropertyGap,
    translation: &impl ResolutionIdentityTranslation,
) -> LoweredDefinitionPropertyGap {
    LoweredDefinitionPropertyGap::new(
        translation.semantic(gap.definition()),
        gap.source_site(),
        gap.kind(),
        translation.semantic(gap.frontier()),
        translation.semantic(gap.reason_semantic()),
    )
}

pub(super) fn remount_call_obligation(
    obligation: &LoweredCallApplicabilityObligation,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredCallApplicabilityObligation> {
    let mut argument_slots = Vec::with_capacity(obligation.argument_slots().len());
    for &slot in obligation.argument_slots() {
        if cancellation.is_cancelled() {
            return None;
        }
        argument_slots.push(translation.semantic(slot));
    }
    let mut extra_result_slots = Vec::with_capacity(obligation.extra_result_slots().len());
    for &slot in obligation.extra_result_slots() {
        if cancellation.is_cancelled() {
            return None;
        }
        extra_result_slots.push(translation.semantic(slot));
    }
    Some(
        LoweredCallApplicabilityObligation::new(
            translation.semantic(obligation.call()),
            translation.semantic(obligation.callee_reference()),
            obligation
                .receiver_slot()
                .map(|slot| translation.semantic(slot)),
            translation.semantic(obligation.result_slot()),
            argument_slots,
            obligation.eligible_rules().to_vec(),
            obligation.explicit_type_argument_count(),
            translation.semantic(obligation.applicability_reason()),
            remount_completion(obligation.completion(), translation, cancellation)?,
        )
        .with_extra_result_slots(extra_result_slots)
        .with_type_argument_slots(
            obligation
                .type_argument_slots()
                .iter()
                .map(|&slot| translation.semantic(slot))
                .collect::<Vec<_>>(),
        )
        .with_owner_type_arguments(
            obligation
                .owner_type_segment()
                .map(|slot| translation.semantic(slot)),
            obligation
                .owner_type_argument_slots()
                .iter()
                .map(|&slot| translation.semantic(slot))
                .collect::<Vec<_>>(),
        )
        .with_expected_result_slot(
            obligation
                .expected_result_slot()
                .map(|slot| translation.semantic(slot)),
        ),
    )
}

pub(super) fn remount_callable_signature(
    signature: &LoweredCallableSignatureProperty,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<LoweredCallableSignatureProperty> {
    let mut parameters = Vec::with_capacity(signature.parameters().len());
    for parameter in signature.parameters() {
        if cancellation.is_cancelled() {
            return None;
        }
        parameters.push(LoweredCallableParameterProperty::new(
            parameter.ordinal(),
            translation.semantic(parameter.definition()),
            translation.semantic(parameter.slot()),
            parameter.repeated(),
        ));
    }
    let mut result_types = Vec::with_capacity(signature.result_types().len());
    for result in signature.result_types() {
        if cancellation.is_cancelled() {
            return None;
        }
        result_types.push(LoweredCallableResultTypeProperty::new(
            result.ordinal(),
            translation.semantic(result.slot()),
        ));
    }
    Some(
        LoweredCallableSignatureProperty::new(
            translation.semantic(signature.definition()),
            signature.type_parameter_count(),
            parameters,
            remount_completion(signature.completion(), translation, cancellation)?,
        )
        .with_result_types(result_types)
        .with_result_bindings(signature.result_bindings())
        .with_receiver(signature.receiver())
        .with_result_type_parameter(signature.result_type_parameter())
        .with_result_owner_type_parameter(signature.result_owner_type_parameter()),
    )
}

/// One immutable copy rule, which crosses the mount seam on its own as well as
/// inside a `LoweredTypeTransfer`.
pub(super) fn remount_type_transfer_rule(
    rule: &TypeTransferRule,
    translation: &impl ResolutionIdentityTranslation,
    cancellation: &CancellationToken,
) -> Option<TypeTransferRule> {
    Some(TypeTransferRule::new_with_reference_indirection(
        translation.semantic(rule.semantic()),
        translation.semantic(rule.target_slot()),
        rule.indirection_delta(),
        rule.reference_indirection_delta(),
        rule.value_transform(),
        remount_completion(rule.completion(), translation, cancellation)?,
    ))
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;

    use crate::analyzer::store::resolution_prepare::{
        ResolutionInteriorPreparation, prepare_resolution_bundle_with_unit_keys,
    };

    use super::super::local_identity::{
        ResolutionIdentityCatalogBuilder, ResolutionSemanticIdentity,
    };
    use super::super::{
        lower_resolution_facts_with_identity_catalog, rich_java_resolution_facts_for_test,
    };
    use super::*;

    fn prepared(
        artifact: &LoweredResolutionFactsWithIdentityCatalog,
    ) -> Box<crate::analyzer::store::resolution::PreparedResolutionBundle> {
        let ResolutionInteriorPreparation::Prepared(bundle) =
            prepare_resolution_bundle_with_unit_keys(artifact, None, &CancellationToken::default())
        else {
            panic!("uncancelled remount preparation must finish")
        };
        bundle
    }

    #[test]
    fn remount_matches_final_source_lowering_and_preserves_prepared_interior() {
        let facts = rich_java_resolution_facts_for_test();
        let provisional = BindingFragmentId::for_test(b"fragment-31");
        let final_fragment = BindingFragmentId::for_test(b"fragment-a7");
        let provisional_artifact =
            crate::analyzer::resolution::lower_resolution_facts_for_selection(
                provisional,
                crate::analyzer::resolution::test_shared_names(),
                Language::Java,
                &facts,
            );
        let provisional_bundle = prepared(&provisional_artifact);

        let remounted = provisional_artifact
            .remount(final_fragment, &CancellationToken::default())
            .expect("uncancelled remount must finish");
        let final_oracle = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            final_fragment,
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &facts,
        );

        assert_eq!(remounted.lexical(), final_oracle.lexical());
        assert_eq!(remounted.typed(), final_oracle.typed());
        assert_eq!(remounted.common(), final_oracle.common());
        assert_eq!(remounted.identities(), final_oracle.identities());
        assert_eq!(provisional_bundle, prepared(&remounted));
    }

    #[test]
    fn remount_preserves_total_and_reference_indirection_provenance() {
        let provisional = BindingFragmentId::for_test(b"fragment-22");
        let final_fragment = BindingFragmentId::for_test(b"fragment-55");
        let mut identities = ResolutionIdentityCatalogBuilder::new(
            provisional,
            crate::analyzer::resolution::test_shared_names(),
        );
        let source_slot = identities.semantic(ResolutionSemanticIdentity::fragment_local([1; 32]));
        let target_slot = identities.semantic(ResolutionSemanticIdentity::fragment_local([2; 32]));
        let rule_semantic =
            identities.semantic(ResolutionSemanticIdentity::fragment_local([3; 32]));
        let type_identity =
            identities.semantic(ResolutionSemanticIdentity::fragment_local([4; 32]));
        let catalog = identities.finish();
        let (remounted_catalog, translation) = catalog
            .remount(final_fragment, &CancellationToken::default())
            .expect("uncancelled catalog remount must finish");

        let value = ResolutionSlotValue::runtime(
            ResolutionTypeRef::new_with_reference_indirection(type_identity, 3, 2),
            true,
        );
        let remounted_value = remount_slot_value(value, &translation);
        assert_eq!(remounted_value.ty().indirection(), 3);
        assert_eq!(remounted_value.ty().reference_indirection(), 2);
        assert_eq!(
            remounted_value.ty().identity(),
            // The catalog's fourth semantic, so position 3: a local key is
            // the catalog position and the positions are dense from zero.
            SemanticId::local(final_fragment.ordinal(), 3)
        );
        assert_eq!(remounted_value.addressable(), Some(true));

        let transfer = LoweredTypeTransfer::new(
            source_slot,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new_with_reference_indirection(
                rule_semantic,
                target_slot,
                2,
                1,
                super::super::model::TypeTransferValueTransform::Preserve,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(rule_semantic),
                ]),
            ),
        );
        let remounted_transfer =
            remount_transfer(&transfer, &translation, &CancellationToken::default())
                .expect("uncancelled transfer remount must finish");
        assert_eq!(remounted_transfer.rule().indirection_delta(), 2);
        assert_eq!(remounted_transfer.rule().reference_indirection_delta(), 1);
        assert_eq!(
            remounted_transfer.rule().semantic(),
            SemanticId::local(final_fragment.ordinal(), 2)
        );
        assert_eq!(remounted_catalog.fragment(), final_fragment);
    }

    #[test]
    fn remount_stops_at_a_deterministic_cancellation_checkpoint() {
        let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(b"fragment-61"),
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &rich_java_resolution_facts_for_test(),
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(17);

        assert!(
            artifact
                .remount(BindingFragmentId::for_test(b"fragment-62"), &cancellation)
                .is_none()
        );
        assert!(cancellation.is_cancelled());
    }
}
