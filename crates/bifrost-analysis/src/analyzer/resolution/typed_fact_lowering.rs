//! File-local resolution facts lowered into target-independent typed rows.
//!
//! This bridge complements lexical [`super::fact_lowering`] without resolving
//! any reference to a declaration. It converts dense file-local IDs into the
//! same stable identities used by the binding fragment, retains projection
//! intent as data, and emits copy rules rather than precomputed transfer
//! values. The result is immutable and operation-bounded; it is neither a
//! workspace arena nor a cache.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, PositionedIdentifierFact, ResolutionCallArgumentFact,
    ResolutionCallableParameterFact, ResolutionConstructionRequirementFact,
    ResolutionConstructionRequirementKind, ResolutionEngineRuleKind, ResolutionGapKind,
    ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeKind,
    ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionSupertypeFact,
    ResolutionSupertypeKind, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

use crate::hash::{HashMap, HashSet};

use super::coverage::LoweringGapOrigin;
use super::fact_lowering::{
    definition_semantic, definition_semantic_identity, gap_reason_semantic,
    gap_reason_semantic_identity, lookup_routes, reference_semantic_identity,
    scope_head_node_identity, site_type_frontier_semantic, site_type_frontier_semantic_identity,
    type_slot_semantic_identity,
};
use super::local_identity::{ResolutionIdentityCatalogBuilder, ResolutionSemanticIdentity};
use super::model::{
    BindingFragmentId, BindingNodeId, ResolutionCompletion, ResolutionIncompleteReason,
    ResolutionSlotValue, ResolutionTypeRef, SemanticId, TypeTransferRule,
    TypeTransferValueTransform, TypedFrontierState, clone_completion_with_poll,
};
use super::{binder_namespace_is_declared, never_cancelled};

/// One source-slot association for an immutable copy rule.
///
/// [`TypeTransferRule`] stores the target slot and the pure value transform;
/// the source slot is the normalized lookup key under which a source exposes
/// the rule. `kind` remains explicit because declared-type, observation, and
/// call-flow edges have different semantic roles even when their copy
/// transforms happen to be identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredTypeTransfer {
    source_slot: SemanticId,
    kind: ResolutionTypeTransferKind,
    rule: TypeTransferRule,
}

impl LoweredTypeTransfer {
    pub fn new(
        source_slot: SemanticId,
        kind: ResolutionTypeTransferKind,
        rule: TypeTransferRule,
    ) -> Self {
        assert_ne!(
            source_slot,
            rule.target_slot(),
            "a type transfer cannot be reflexive"
        );
        Self {
            source_slot,
            kind,
            rule,
        }
    }

    pub const fn source_slot(&self) -> SemanticId {
        self.source_slot
    }

    pub const fn kind(&self) -> ResolutionTypeTransferKind {
        self.kind
    }

    pub const fn rule(&self) -> &TypeTransferRule {
        &self.rule
    }
}

/// One syntax-known type value at a stable typed frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredIntrinsicSeed {
    kind: IntrinsicTypeKind,
    frontier: TypedFrontierState,
}

impl LoweredIntrinsicSeed {
    pub fn new(kind: IntrinsicTypeKind, frontier: TypedFrontierState) -> Self {
        Self { kind, frontier }
    }

    pub const fn kind(&self) -> IntrinsicTypeKind {
        self.kind
    }

    pub const fn frontier(&self) -> &TypedFrontierState {
        &self.frontier
    }
}

/// A property to copy only after `reference` binds in the selected revision.
///
/// There is deliberately no target field. The projection evaluator joins the
/// eventual definition semantic to declaration properties after binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredBindingProjection {
    reference: SemanticId,
    output_slot: SemanticId,
    kind: BindingProjectionKind,
}

/// One declared typed frontier, including slots that have no local producer.
///
/// This inventory is distinct from [`LoweredIntrinsicSeed`]: a slot remains
/// part of the immutable typed graph even when its value will arrive only from
/// a selected declaration, a transfer, or a later operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredTypedFrontier {
    slot: SemanticId,
    role: ResolutionTypeSlotRole,
}

impl LoweredTypedFrontier {
    pub const fn new(slot: SemanticId, role: ResolutionTypeSlotRole) -> Self {
        Self { slot, role }
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }

    pub const fn role(&self) -> ResolutionTypeSlotRole {
        self.role
    }
}

/// One exact typed obligation that replaces a qualified reference's coarse
/// lexical gap during seeded resolution.
///
/// Lexical point resolution intentionally remains incomplete for a qualified
/// reference. The combined service may discharge `coarse_gap_reason` only
/// when it consumes this row and explores the qualifier frontier, owner member
/// scope, and exact effective lookup key. `precedence_ordinal` is the same
/// TypeOrValue route ordering encoded by lexical lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredQualifiedSeededRoute {
    reference: SemanticId,
    qualifier_slot: SemanticId,
    lookup: SemanticId,
    namespace: ResolutionNamespace,
    precedence_ordinal: u32,
    projection_output_slot: SemanticId,
    projection_kind: BindingProjectionKind,
    coarse_gap_reason: SemanticId,
}

impl LoweredQualifiedSeededRoute {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        reference: SemanticId,
        qualifier_slot: SemanticId,
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        precedence_ordinal: u32,
        projection_output_slot: SemanticId,
        projection_kind: BindingProjectionKind,
        coarse_gap_reason: SemanticId,
    ) -> Self {
        Self {
            reference,
            qualifier_slot,
            lookup,
            namespace,
            precedence_ordinal,
            projection_output_slot,
            projection_kind,
            coarse_gap_reason,
        }
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn qualifier_slot(&self) -> SemanticId {
        self.qualifier_slot
    }

    pub const fn lookup(&self) -> SemanticId {
        self.lookup
    }

    pub const fn namespace(&self) -> ResolutionNamespace {
        self.namespace
    }

    pub const fn precedence_ordinal(&self) -> u32 {
        self.precedence_ordinal
    }

    pub const fn projection_output_slot(&self) -> SemanticId {
        self.projection_output_slot
    }

    pub const fn projection_kind(&self) -> BindingProjectionKind {
        self.projection_kind
    }

    pub const fn coarse_gap_reason(&self) -> SemanticId {
        self.coarse_gap_reason
    }
}

impl LoweredBindingProjection {
    pub const fn new(
        reference: SemanticId,
        output_slot: SemanticId,
        kind: BindingProjectionKind,
    ) -> Self {
        Self {
            reference,
            output_slot,
            kind,
        }
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn output_slot(&self) -> SemanticId {
        self.output_slot
    }

    pub const fn kind(&self) -> BindingProjectionKind {
        self.kind
    }
}

/// A declared type property indexed by its declaration definition semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredDeclarationTypeProperty {
    definition: SemanticId,
    slot: SemanticId,
    role: DeclarationTypeRole,
}

impl LoweredDeclarationTypeProperty {
    pub const fn new(definition: SemanticId, slot: SemanticId, role: DeclarationTypeRole) -> Self {
        Self {
            definition,
            slot,
            role,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }

    pub const fn role(&self) -> DeclarationTypeRole {
        self.role
    }
}

/// One declaration's source-known access-control spelling.
///
/// This positive row is deliberately distinct from
/// [`LoweredDefinitionPropertyGap`]. A missing visibility gap cannot prove a
/// declaration public: it can also mean that a producer or persisted rowset
/// omitted the access-control family. Consumers may discharge Java visibility
/// evidence only after reading this row and observing [`DeclaredVisibility::Public`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredDeclarationVisibilityProperty {
    definition: SemanticId,
    visibility: DeclaredVisibility,
}

impl LoweredDeclarationVisibilityProperty {
    pub const fn new(definition: SemanticId, visibility: DeclaredVisibility) -> Self {
        Self {
            definition,
            visibility,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn visibility(&self) -> DeclaredVisibility {
        self.visibility
    }
}

/// The binding-node entry point for members declared by one type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredMemberScopeProperty {
    definition: SemanticId,
    scope_head: BindingNodeId,
}

impl LoweredMemberScopeProperty {
    pub const fn new(definition: SemanticId, scope_head: BindingNodeId) -> Self {
        Self {
            definition,
            scope_head,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn scope_head(&self) -> BindingNodeId {
        self.scope_head
    }
}

/// A member's declaring-type property.
///
/// `owner_scope_head` repeats the selected owner's normalized member-scope
/// entry point intentionally: a resolved member can seed the next qualified
/// lookup without reconstructing a scope ID or reading source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredMemberOwnerProperty {
    definition: SemanticId,
    owner_definition: SemanticId,
    owner_scope_head: BindingNodeId,
    kind: ResolutionMemberKind,
    access: ResolutionMemberAccess,
    qualifier_compatibility: ResolutionMemberQualifierCompatibility,
}

impl LoweredMemberOwnerProperty {
    pub const fn new(
        definition: SemanticId,
        owner_definition: SemanticId,
        owner_scope_head: BindingNodeId,
        kind: ResolutionMemberKind,
        access: ResolutionMemberAccess,
        qualifier_compatibility: ResolutionMemberQualifierCompatibility,
    ) -> Self {
        Self {
            definition,
            owner_definition,
            owner_scope_head,
            kind,
            access,
            qualifier_compatibility,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn owner_definition(&self) -> SemanticId {
        self.owner_definition
    }

    pub const fn owner_scope_head(&self) -> BindingNodeId {
        self.owner_scope_head
    }

    pub const fn kind(&self) -> ResolutionMemberKind {
        self.kind
    }

    pub const fn access(&self) -> ResolutionMemberAccess {
        self.access
    }

    pub const fn qualifier_compatibility(&self) -> ResolutionMemberQualifierCompatibility {
        self.qualifier_compatibility
    }
}

/// A construction-only requirement indexed by the constructed definition.
///
/// Nested-type lookup uses [`LoweredMemberOwnerProperty`]. This separate row
/// prevents an enclosing-instance requirement from changing the name-lookup
/// qualifier from a type object into a runtime value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredConstructionRequirementProperty {
    definition: SemanticId,
    required_owner_definition: SemanticId,
    kind: ResolutionConstructionRequirementKind,
}

impl LoweredConstructionRequirementProperty {
    pub const fn new(
        definition: SemanticId,
        required_owner_definition: SemanticId,
        kind: ResolutionConstructionRequirementKind,
    ) -> Self {
        Self {
            definition,
            required_owner_definition,
            kind,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn required_owner_definition(&self) -> SemanticId {
        self.required_owner_definition
    }

    pub const fn kind(&self) -> ResolutionConstructionRequirementKind {
        self.kind
    }
}

/// A declared hierarchy edge whose target remains an unresolved reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredSupertypeProperty {
    definition: SemanticId,
    reference: SemanticId,
    frontier: SemanticId,
    kind: ResolutionSupertypeKind,
}

impl LoweredSupertypeProperty {
    pub const fn new(
        definition: SemanticId,
        reference: SemanticId,
        frontier: SemanticId,
        kind: ResolutionSupertypeKind,
    ) -> Self {
        Self {
            definition,
            reference,
            frontier,
            kind,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn frontier(&self) -> SemanticId {
        self.frontier
    }

    pub const fn kind(&self) -> ResolutionSupertypeKind {
        self.kind
    }
}

/// Site-local incomplete evidence reachable through its owning definition.
///
/// The `frontier` is exactly the stable type-slot or site-property identity
/// used by lexical coverage lowering. Explicit supertype gaps are owned by the
/// subtype declaration; implicit-root and implicit-constructor gaps are owned
/// directly by the affected type declaration. No synthetic property gap is
/// left without a definition from which a projection evaluator can reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredDefinitionPropertyGap {
    definition: SemanticId,
    source_site: ResolutionSiteId,
    kind: ResolutionGapKind,
    frontier: SemanticId,
    reason_semantic: SemanticId,
}

/// One unresolved call whose arguments must be checked against the selected
/// callable candidate before the result projection becomes exact.
///
/// `applicability_reason` is deliberately present in `completion` until the
/// applicability evaluator consumes this obligation. Lowering argument rows
/// is not evidence that overload selection, conversions, arity, or repeated
/// parameters have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredCallApplicabilityObligation {
    call: SemanticId,
    callee_reference: SemanticId,
    receiver_slot: Option<SemanticId>,
    result_slot: SemanticId,
    argument_slots: Box<[SemanticId]>,
    eligible_rules: Box<[ResolutionEngineRuleKind]>,
    explicit_type_argument_count: u32,
    applicability_reason: SemanticId,
    completion: ResolutionCompletion,
}

impl LoweredCallApplicabilityObligation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call: SemanticId,
        callee_reference: SemanticId,
        receiver_slot: Option<SemanticId>,
        result_slot: SemanticId,
        argument_slots: impl Into<Box<[SemanticId]>>,
        eligible_rules: impl Into<Box<[ResolutionEngineRuleKind]>>,
        explicit_type_argument_count: u32,
        applicability_reason: SemanticId,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            call,
            callee_reference,
            receiver_slot,
            result_slot,
            argument_slots: argument_slots.into(),
            eligible_rules: eligible_rules.into(),
            explicit_type_argument_count,
            applicability_reason,
            completion,
        }
    }

    pub const fn call(&self) -> SemanticId {
        self.call
    }

    pub const fn callee_reference(&self) -> SemanticId {
        self.callee_reference
    }

    pub const fn receiver_slot(&self) -> Option<SemanticId> {
        self.receiver_slot
    }

    pub const fn result_slot(&self) -> SemanticId {
        self.result_slot
    }

    pub fn argument_slots(&self) -> &[SemanticId] {
        &self.argument_slots
    }

    pub fn eligible_rules(&self) -> &[ResolutionEngineRuleKind] {
        &self.eligible_rules
    }

    pub const fn explicit_type_argument_count(&self) -> u32 {
        self.explicit_type_argument_count
    }

    pub const fn applicability_reason(&self) -> SemanticId {
        self.applicability_reason
    }

    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

/// One ordered parameter in a callable declaration's local signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredCallableParameterProperty {
    ordinal: u32,
    definition: SemanticId,
    slot: SemanticId,
    repeated: bool,
}

impl LoweredCallableParameterProperty {
    pub const fn new(
        ordinal: u32,
        definition: SemanticId,
        slot: SemanticId,
        repeated: bool,
    ) -> Self {
        Self {
            ordinal,
            definition,
            slot,
            repeated,
        }
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }

    pub const fn repeated(&self) -> bool {
        self.repeated
    }
}

/// The target-independent local signature indexed by callable definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredCallableSignatureProperty {
    definition: SemanticId,
    type_parameter_count: u32,
    parameters: Box<[LoweredCallableParameterProperty]>,
    completion: ResolutionCompletion,
}

impl LoweredCallableSignatureProperty {
    pub fn new(
        definition: SemanticId,
        type_parameter_count: u32,
        parameters: impl Into<Box<[LoweredCallableParameterProperty]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        let mut parameters = parameters.into().into_vec();
        parameters.sort_unstable_by_key(|parameter| parameter.ordinal);
        let Some(signature) = Self::from_canonical_parts_with_poll(
            definition,
            type_parameter_count,
            parameters.into_boxed_slice(),
            completion,
            &mut never_cancelled,
        ) else {
            unreachable!("the never-cancelled signature poll returned cancellation")
        };
        signature
    }

    pub(super) fn from_canonical_parts_with_poll<P>(
        definition: SemanticId,
        type_parameter_count: u32,
        parameters: Box<[LoweredCallableParameterProperty]>,
        completion: ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let mut parameter_definitions = HashSet::default();
        for (expected, parameter) in parameters.iter().enumerate() {
            if cancelled() {
                return None;
            }
            assert_eq!(
                usize::try_from(parameter.ordinal).expect("u32 ordinal fits usize"),
                expected,
                "callable {definition:?} parameter ordinals must be contiguous from zero"
            );
            assert!(
                parameter_definitions.insert(parameter.definition),
                "callable {definition:?} repeats parameter definition {:?}",
                parameter.definition
            );
            if parameter.repeated {
                assert_eq!(
                    expected + 1,
                    parameters.len(),
                    "repeated parameter must be last in callable {definition:?}"
                );
            }
        }
        Some(Self {
            definition,
            type_parameter_count,
            parameters,
            completion,
        })
    }

    pub(super) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let mut parameters = Vec::with_capacity(self.parameters.len());
        for &parameter in self.parameters.iter() {
            if cancelled() {
                return None;
            }
            parameters.push(parameter);
        }
        Self::from_canonical_parts_with_poll(
            self.definition,
            self.type_parameter_count,
            parameters.into_boxed_slice(),
            clone_completion_with_poll(&self.completion, cancelled)?,
            cancelled,
        )
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn type_parameter_count(&self) -> u32 {
        self.type_parameter_count
    }

    pub fn parameters(&self) -> &[LoweredCallableParameterProperty] {
        &self.parameters
    }

    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

impl LoweredDefinitionPropertyGap {
    pub const fn new(
        definition: SemanticId,
        source_site: ResolutionSiteId,
        kind: ResolutionGapKind,
        frontier: SemanticId,
        reason_semantic: SemanticId,
    ) -> Self {
        Self {
            definition,
            source_site,
            kind,
            frontier,
            reason_semantic,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn source_site(&self) -> ResolutionSiteId {
        self.source_site
    }

    pub const fn kind(&self) -> ResolutionGapKind {
        self.kind
    }

    pub const fn frontier(&self) -> SemanticId {
        self.frontier
    }

    pub const fn reason_semantic(&self) -> SemanticId {
        self.reason_semantic
    }
}

/// Immutable target-independent typed half of one binding fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredTypedFragment {
    fragment: BindingFragmentId,
    language: Language,
    frontiers: Vec<LoweredTypedFrontier>,
    transfers: Vec<LoweredTypeTransfer>,
    intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
    projections: Vec<LoweredBindingProjection>,
    qualified_routes: Vec<LoweredQualifiedSeededRoute>,
    declaration_types: Vec<LoweredDeclarationTypeProperty>,
    declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
    member_scopes: Vec<LoweredMemberScopeProperty>,
    member_owners: Vec<LoweredMemberOwnerProperty>,
    construction_requirements: Vec<LoweredConstructionRequirementProperty>,
    supertypes: Vec<LoweredSupertypeProperty>,
    property_gaps: Vec<LoweredDefinitionPropertyGap>,
    call_obligations: Vec<LoweredCallApplicabilityObligation>,
    callable_signatures: Vec<LoweredCallableSignatureProperty>,
}

impl LoweredTypedFragment {
    /// Rebuild one immutable typed fragment from normalized persisted rows.
    ///
    /// Top-level row order is not part of the contract. This constructor
    /// restores the same canonical order and graph invariants as source-fact
    /// lowering, so hydration cannot create an artifact source lowering would
    /// have rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fragment: BindingFragmentId,
        language: Language,
        mut frontiers: Vec<LoweredTypedFrontier>,
        mut transfers: Vec<LoweredTypeTransfer>,
        mut intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
        mut projections: Vec<LoweredBindingProjection>,
        mut qualified_routes: Vec<LoweredQualifiedSeededRoute>,
        mut declaration_types: Vec<LoweredDeclarationTypeProperty>,
        mut declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
        mut member_scopes: Vec<LoweredMemberScopeProperty>,
        mut member_owners: Vec<LoweredMemberOwnerProperty>,
        mut construction_requirements: Vec<LoweredConstructionRequirementProperty>,
        mut supertypes: Vec<LoweredSupertypeProperty>,
        mut property_gaps: Vec<LoweredDefinitionPropertyGap>,
        mut call_obligations: Vec<LoweredCallApplicabilityObligation>,
        mut callable_signatures: Vec<LoweredCallableSignatureProperty>,
    ) -> Self {
        assert_ne!(language, Language::None, "typed fragment needs a language");
        frontiers.sort_by_key(frontier_sort_key);
        transfers.sort_by_key(transfer_sort_key);
        intrinsic_seeds.sort_by_key(intrinsic_sort_key);
        projections.sort_by_key(projection_sort_key);
        qualified_routes.sort_by_key(qualified_route_sort_key);
        declaration_types.sort_by_key(declaration_type_sort_key);
        declaration_visibilities.sort_unstable();
        member_scopes.sort_unstable();
        member_owners.sort_by_key(member_owner_sort_key);
        construction_requirements.sort_by_key(construction_requirement_sort_key);
        supertypes.sort_by_key(supertype_sort_key);
        property_gaps.sort_by_key(property_gap_sort_key);
        call_obligations.sort_by_key(call_obligation_sort_key);
        callable_signatures.sort_by_key(callable_signature_sort_key);

        let lowered = Self {
            fragment,
            language,
            frontiers,
            transfers,
            intrinsic_seeds,
            projections,
            qualified_routes,
            declaration_types,
            declaration_visibilities,
            member_scopes,
            member_owners,
            construction_requirements,
            supertypes,
            property_gaps,
            call_obligations,
            callable_signatures,
        };
        lowered.assert_normalized_graph();
        lowered
    }

    fn assert_normalized_graph(&self) {
        assert!(
            self.frontiers
                .windows(2)
                .all(|pair| pair[0].slot != pair[1].slot),
            "one typed frontier per stable slot is required"
        );
        let inventory = self
            .frontiers
            .iter()
            .map(|frontier| (frontier.slot, frontier.role))
            .collect::<HashMap<_, _>>();
        assert_unique_lowered_rows(self);
        validate_lowered_output_producers(
            &self.transfers,
            &self.intrinsic_seeds,
            &self.projections,
        );

        for transfer in &self.transfers {
            assert_ne!(
                transfer.source_slot,
                transfer.rule.target_slot(),
                "a type transfer cannot be reflexive"
            );
            let source_role =
                assert_declared_frontier(&inventory, transfer.source_slot, "type-transfer source");
            let output_role = assert_declared_frontier(
                &inventory,
                transfer.rule.target_slot(),
                "type-transfer target",
            );
            assert_eq!(
                output_role,
                transfer_output_role(transfer.kind),
                "type-transfer kind and output role disagree"
            );
            if transfer.kind == ResolutionTypeTransferKind::DeclaredType {
                assert_eq!(
                    source_role,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                    "declared-type transfer input must retain a type object"
                );
            }
            assert_persistable_typed_completion(transfer.rule.completion(), "type-transfer rule");
        }
        for seed in &self.intrinsic_seeds {
            let role =
                assert_declared_frontier(&inventory, seed.frontier.slot(), "intrinsic type seed");
            assert_persistable_typed_completion(seed.frontier.completion(), "intrinsic type seed");
            assert_intrinsic_seed_matches_role(seed, role);
        }
        for projection in &self.projections {
            let output_role =
                assert_declared_frontier(&inventory, projection.output_slot, "binding projection");
            assert_eq!(
                output_role,
                projection_contract(projection.kind).1,
                "binding projection kind and output role disagree"
            );
        }
        let projection_keys = self
            .projections
            .iter()
            .map(|projection| {
                (
                    projection.reference,
                    projection.output_slot,
                    projection.kind,
                )
            })
            .collect::<HashSet<_>>();
        let projection_outputs = self
            .projections
            .iter()
            .map(|projection| (projection.reference, projection.output_slot))
            .collect::<HashSet<_>>();
        for route in &self.qualified_routes {
            let qualifier_role = assert_declared_frontier(
                &inventory,
                route.qualifier_slot,
                "qualified route qualifier",
            );
            assert_declared_frontier(
                &inventory,
                route.projection_output_slot,
                "qualified route projection",
            );
            if route.projection_kind == BindingProjectionKind::TargetConstructorOwnerType {
                assert_eq!(
                    qualifier_role,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                    "constructor projection qualifier must retain a type object"
                );
            }
            assert!(
                projection_keys.contains(&(
                    route.reference,
                    route.projection_output_slot,
                    route.projection_kind,
                )),
                "qualified route must name its exact binding projection"
            );
        }
        assert_source_lowerable_qualified_routes(&self.qualified_routes);

        for property in &self.declaration_types {
            let role =
                assert_declared_frontier(&inventory, property.slot, "declaration type property");
            assert_eq!(
                role,
                ResolutionTypeSlotRole::DeclaredValue,
                "declaration type property must name a DeclaredValue frontier"
            );
        }
        let parameter_declarations = self
            .declaration_types
            .iter()
            .filter(|property| property.role == DeclarationTypeRole::Parameter)
            .map(|property| (property.definition, property.slot))
            .collect::<HashSet<_>>();
        for property in &self.supertypes {
            let role =
                assert_declared_frontier(&inventory, property.frontier, "supertype property");
            assert_eq!(
                role,
                ResolutionTypeSlotRole::TargetTypeIdentity,
                "supertype property must name a TargetTypeIdentity frontier"
            );
            assert!(
                projection_keys.contains(&(
                    property.reference,
                    property.frontier,
                    BindingProjectionKind::TargetTypeIdentity,
                )),
                "supertype property requires its exact TargetTypeIdentity projection"
            );
        }
        let declaration_visibilities = self
            .declaration_visibilities
            .iter()
            .map(|property| (property.definition, property.visibility))
            .collect::<HashMap<_, _>>();
        if self.language == Language::Java {
            let eligible_definitions = self
                .member_scopes
                .iter()
                .map(|property| property.definition)
                .chain(
                    self.member_owners
                        .iter()
                        .map(|property| property.definition),
                )
                .collect::<HashSet<_>>();
            assert_eq!(
                declaration_visibilities
                    .keys()
                    .copied()
                    .collect::<HashSet<_>>(),
                eligible_definitions,
                "Java declaration-visibility inventory must equal supported type and member definitions"
            );
            assert!(
                self.declaration_visibilities
                    .iter()
                    .all(|property| matches!(
                        property.visibility,
                        DeclaredVisibility::Public
                            | DeclaredVisibility::Protected
                            | DeclaredVisibility::PackagePrivate
                            | DeclaredVisibility::Private
                    )),
                "Java declaration visibility must use one of Java's four access levels"
            );
        }
        for gap in &self.property_gaps {
            assert!(
                matches!(
                    gap.kind,
                    ResolutionGapKind::ImplicitConstructor
                        | ResolutionGapKind::UnsupportedHierarchyTraversal
                        | ResolutionGapKind::UnsupportedVisibility
                ),
                "definition property gap kind is not source-lowerable"
            );
            if !inventory.contains_key(&gap.frontier) {
                assert_eq!(
                    gap.frontier,
                    site_type_frontier_semantic(self.fragment, gap.source_site),
                    "only a synthetic site property gap may omit a typed-frontier row"
                );
            }
            if gap.kind == ResolutionGapKind::UnsupportedVisibility {
                assert_eq!(
                    gap.definition,
                    definition_semantic(self.fragment, gap.source_site),
                    "visibility gap must remain owned by its exact declaration"
                );
                let visibility = declaration_visibilities
                    .get(&gap.definition)
                    .unwrap_or_else(|| {
                        panic!(
                            "visibility gap definition {:?} has no positive visibility row",
                            gap.definition
                        )
                    });
                assert_ne!(
                    *visibility,
                    DeclaredVisibility::Public,
                    "public declaration cannot retain unsupported visibility evidence"
                );
                assert_eq!(
                    gap.reason_semantic,
                    gap_reason_semantic(
                        self.fragment,
                        gap.source_site,
                        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedVisibility),
                    ),
                    "visibility gap reason must retain exact declaration provenance"
                );
            }
        }
        for property in &self.declaration_visibilities {
            let gap_sources = self
                .property_gaps
                .iter()
                .filter(|gap| {
                    gap.definition == property.definition
                        && gap.kind == ResolutionGapKind::UnsupportedVisibility
                })
                .map(|gap| (gap.source_site, gap.reason_semantic))
                .collect::<HashSet<_>>();
            if property.visibility == DeclaredVisibility::Public {
                assert!(
                    gap_sources.is_empty(),
                    "public declaration cannot retain unsupported visibility evidence"
                );
            } else {
                assert_eq!(
                    gap_sources.len(),
                    1,
                    "non-public declaration requires one exact visibility gap provenance"
                );
            }
        }
        for obligation in &self.call_obligations {
            if let Some(receiver) = obligation.receiver_slot {
                assert_eq!(
                    assert_declared_frontier(&inventory, receiver, "call receiver"),
                    ResolutionTypeSlotRole::Receiver,
                    "call receiver must name a Receiver frontier"
                );
            }
            assert_eq!(
                assert_declared_frontier(&inventory, obligation.result_slot, "call result"),
                ResolutionTypeSlotRole::CallResult,
                "call result must name a CallResult frontier"
            );
            for &argument in obligation.argument_slots.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, argument, "call argument"),
                    ResolutionTypeSlotRole::Argument,
                    "call argument must name an Argument frontier"
                );
            }
            assert!(
                projection_outputs.contains(&(obligation.callee_reference, obligation.result_slot)),
                "call applicability obligation requires its result binding projection"
            );
            assert!(
                obligation.completion.contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(
                        obligation.applicability_reason,
                    ),
                ),
                "call applicability completion must retain its declared applicability reason"
            );
            assert_persistable_typed_completion(
                &obligation.completion,
                "call applicability obligation",
            );
        }
        let mut parameter_definitions = HashSet::default();
        for signature in &self.callable_signatures {
            for parameter in signature.parameters.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, parameter.slot, "callable parameter"),
                    ResolutionTypeSlotRole::DeclaredValue,
                    "callable parameter must name a DeclaredValue frontier"
                );
                assert!(
                    parameter_declarations.contains(&(parameter.definition, parameter.slot)),
                    "callable parameter requires its matching Parameter declaration type property"
                );
                assert!(
                    parameter_definitions.insert(parameter.definition),
                    "callable parameter definition may belong to only one signature"
                );
            }
            assert_persistable_typed_completion(&signature.completion, "callable signature");
        }

        let member_scopes = self
            .member_scopes
            .iter()
            .map(|property| (property.definition, property.scope_head))
            .collect::<HashSet<_>>();
        for owner in &self.member_owners {
            assert!(
                member_scopes.contains(&(owner.owner_definition, owner.owner_scope_head)),
                "member owner must name its declaring type's exact member scope"
            );
        }
        for requirement in &self.construction_requirements {
            assert!(
                self.member_owners.iter().any(|owner| {
                    owner.definition == requirement.definition
                        && owner.owner_definition == requirement.required_owner_definition
                        && owner.kind == ResolutionMemberKind::NestedType
                        && owner.access == ResolutionMemberAccess::Type
                }),
                "construction requirement requires matching nested-type ownership"
            );
        }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn language(&self) -> Language {
        self.language
    }

    pub fn frontiers(&self) -> &[LoweredTypedFrontier] {
        &self.frontiers
    }

    pub fn transfers(&self) -> &[LoweredTypeTransfer] {
        &self.transfers
    }

    pub fn intrinsic_seeds(&self) -> &[LoweredIntrinsicSeed] {
        &self.intrinsic_seeds
    }

    pub fn projections(&self) -> &[LoweredBindingProjection] {
        &self.projections
    }

    pub fn qualified_routes(&self) -> &[LoweredQualifiedSeededRoute] {
        &self.qualified_routes
    }

    pub fn declaration_types(&self) -> &[LoweredDeclarationTypeProperty] {
        &self.declaration_types
    }

    pub fn declaration_visibilities(&self) -> &[LoweredDeclarationVisibilityProperty] {
        &self.declaration_visibilities
    }

    pub fn member_scopes(&self) -> &[LoweredMemberScopeProperty] {
        &self.member_scopes
    }

    pub fn member_owners(&self) -> &[LoweredMemberOwnerProperty] {
        &self.member_owners
    }

    pub fn construction_requirements(&self) -> &[LoweredConstructionRequirementProperty] {
        &self.construction_requirements
    }

    pub fn supertypes(&self) -> &[LoweredSupertypeProperty] {
        &self.supertypes
    }

    pub fn property_gaps(&self) -> &[LoweredDefinitionPropertyGap] {
        &self.property_gaps
    }

    pub fn call_obligations(&self) -> &[LoweredCallApplicabilityObligation] {
        &self.call_obligations
    }

    pub fn callable_signatures(&self) -> &[LoweredCallableSignatureProperty] {
        &self.callable_signatures
    }
}

/// Canonical declaration-owned properties emitted with one typed fragment.
struct LoweredDefinitionProperties {
    declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
    member_owners: Vec<LoweredMemberOwnerProperty>,
    construction_requirements: Vec<LoweredConstructionRequirementProperty>,
    supertypes: Vec<LoweredSupertypeProperty>,
    property_gaps: Vec<LoweredDefinitionPropertyGap>,
}

/// Lower the typed relations of one immutable file-local fact set.
///
/// The operation does not inspect source and cannot choose a cross-file
/// target. It validates the dense fact graph first, then derives every output
/// identity solely from the fragment and stable source IDs. Output vectors are
/// canonical under arbitrary input-row permutation.
pub fn lower_typed_resolution_facts(
    fragment: BindingFragmentId,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredTypedFragment {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment);
    lower_typed_resolution_facts_with_identities(&mut identities, language, facts)
}

pub(super) fn lower_typed_resolution_facts_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredTypedFragment {
    assert_ne!(language, Language::None, "resolution facts need a language");
    let fragment = identities.fragment();
    let index = TypedFactIndex::new(facts);
    index.validate_scope_forest();
    index.validate_remaining_typed_relations(facts);
    validate_output_producers(facts, &index);

    let gaps_by_site = gaps_by_site(facts);
    let frontiers = facts
        .type_slots
        .iter()
        .map(|slot| {
            LoweredTypedFrontier::new(
                identities.semantic(type_slot_semantic_identity(slot.id)),
                slot.role,
            )
        })
        .collect::<Vec<_>>();

    let mut seen_transfers = HashSet::default();
    let mut transfers = Vec::with_capacity(facts.type_transfers.len());
    for &fact in &facts.type_transfers {
        assert!(
            seen_transfers.insert(fact),
            "duplicate type-transfer fact: {fact:?}"
        );
        let input = index.slot(fact.input);
        let output = index.slot(fact.output);
        assert_ne!(
            fact.input, fact.output,
            "a type transfer cannot be reflexive"
        );
        validate_transfer_roles(fact, input.role, output.role);
        let source_slot = identities.semantic(type_slot_semantic_identity(fact.input));
        let target_slot = identities.semantic(type_slot_semantic_identity(fact.output));
        let completion = completion_for_sites(identities, &gaps_by_site, [input.site, output.site]);
        transfers.push(LoweredTypeTransfer::new(
            source_slot,
            fact.kind,
            TypeTransferRule::new(
                identities.semantic(transfer_rule_semantic_identity(fact)),
                target_slot,
                i64::from(fact.indirection_delta),
                lower_value_transform(fact.value_transform),
                completion,
            ),
        ));
    }

    let mut seen_intrinsics = HashSet::default();
    let mut intrinsic_seeds = Vec::with_capacity(facts.intrinsic_type_seeds.len());
    for &fact in &facts.intrinsic_type_seeds {
        assert!(
            seen_intrinsics.insert(fact),
            "duplicate intrinsic type seed: {fact:?}"
        );
        let output = index.slot(fact.output);
        let ty = ResolutionTypeRef::new(
            identities.semantic(intrinsic_type_semantic_identity(
                language,
                fact.kind,
                index.name(fact.name),
            )),
            u32::from(fact.indirection),
        );
        let (values, unsupported_role) = match output.role {
            ResolutionTypeSlotRole::TargetTypeIdentity => {
                (vec![ResolutionSlotValue::type_object(ty)], None)
            }
            ResolutionTypeSlotRole::ExpressionValue => {
                (vec![ResolutionSlotValue::runtime(ty, false)], None)
            }
            role => (
                Vec::new(),
                Some(ResolutionIncompleteReason::UnsupportedSemantic(
                    identities.semantic(unsupported_intrinsic_role_semantic_identity(
                        fact.output,
                        role,
                    )),
                )),
            ),
        };
        let mut completion = completion_for_sites(identities, &gaps_by_site, [output.site]);
        if let Some(reason) = unsupported_role {
            completion = completion.combine(&ResolutionCompletion::incomplete([reason]));
        }
        intrinsic_seeds.push(LoweredIntrinsicSeed::new(
            fact.kind,
            TypedFrontierState::new(
                identities.semantic(type_slot_semantic_identity(fact.output)),
                values,
                completion,
            ),
        ));
    }

    let mut seen_projections = HashSet::default();
    let mut projections = Vec::with_capacity(facts.binding_projections.len());
    for &fact in &facts.binding_projections {
        assert!(
            seen_projections.insert(fact),
            "duplicate binding projection: {fact:?}"
        );
        validate_projection(fact, &index, facts);
        projections.push(LoweredBindingProjection::new(
            identities.semantic(reference_semantic_identity(fact.reference)),
            identities.semantic(type_slot_semantic_identity(fact.output)),
            fact.kind,
        ));
    }

    let projection_by_reference = facts
        .binding_projections
        .iter()
        .map(|projection| (projection.reference, *projection))
        .collect::<HashMap<_, _>>();
    assert_eq!(
        projection_by_reference.len(),
        facts.binding_projections.len(),
        "one binding projection per reference is required"
    );
    let mut qualified_routes = Vec::new();
    for identifier in index.identifiers.values() {
        let Some(qualifier) = identifier.qualifier else {
            continue;
        };
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        let Some(projection) = projection_by_reference.get(&identifier.site) else {
            // Without a projection output this layer cannot own the typed
            // obligation. The lexical QualifiedReference gap remains live.
            continue;
        };
        let reference = identities.semantic(reference_semantic_identity(identifier.site));
        let coarse_gap_reason = identities.semantic(gap_reason_semantic_identity(
            identifier.site,
            LoweringGapOrigin::QualifiedReference,
        ));
        for &(precedence_ordinal, namespace) in lookup_routes(identifier.namespace) {
            qualified_routes.push(LoweredQualifiedSeededRoute::new(
                reference,
                identities.semantic(type_slot_semantic_identity(qualifier)),
                identities.lookup_semantic(language, namespace, index.name(identifier.name)),
                namespace,
                precedence_ordinal,
                identities.semantic(type_slot_semantic_identity(projection.output)),
                projection.kind,
                coarse_gap_reason,
            ));
        }
    }

    let mut seen_declaration_types = HashSet::default();
    let mut declaration_role_keys = HashSet::default();
    let mut declaration_types = Vec::with_capacity(facts.declaration_type_slots.len());
    for &fact in &facts.declaration_type_slots {
        assert!(
            seen_declaration_types.insert(fact),
            "duplicate declaration type property: {fact:?}"
        );
        validate_declaration_type(fact, &index);
        assert!(
            declaration_role_keys.insert((fact.declaration, fact.role)),
            "one declaration type slot per (definition, role) is required: {fact:?}"
        );
        declaration_types.push(LoweredDeclarationTypeProperty::new(
            identities.semantic(definition_semantic_identity(fact.declaration)),
            identities.semantic(type_slot_semantic_identity(fact.slot)),
            fact.role,
        ));
    }

    let member_scopes = lower_member_scope_properties(identities, &index);
    let definition_properties =
        lower_definition_properties_with_index(identities, language, facts, &index, &member_scopes);
    let LoweredDefinitionProperties {
        declaration_visibilities,
        member_owners,
        construction_requirements,
        supertypes,
        property_gaps,
    } = definition_properties;

    let arguments_by_call = normalized_call_arguments(facts, &index);
    let mut eligible_rules_by_call = HashMap::<_, Vec<_>>::default();
    for eligibility in &facts.engine_rule_eligibilities {
        eligible_rules_by_call
            .entry(eligibility.call)
            .or_default()
            .push(eligibility.rule);
    }
    for rules in eligible_rules_by_call.values_mut() {
        rules.sort_unstable();
        assert!(rules.windows(2).all(|pair| pair[0] != pair[1]));
    }
    let mut call_obligations = Vec::with_capacity(facts.calls.len());
    for &call in &facts.calls {
        let Some(callee_identifier) = index.identifiers.get(&call.callee).copied() else {
            assert!(
                gaps_by_site.contains_key(&call.callee),
                "call without a reference callee requires explicit extracted gap evidence: {call:?}"
            );
            continue;
        };
        assert_eq!(callee_identifier.role, ResolutionIdentifierRole::Reference);
        let call_semantic = identities.semantic(call_semantic_identity(call.call));
        let applicability_reason = identities.semantic(gap_reason_semantic_identity(
            call.callee,
            LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability),
        ));
        let arguments = arguments_by_call
            .get(&call.call)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let argument_slots = arguments
            .iter()
            .map(|argument| identities.semantic(type_slot_semantic_identity(argument.value)))
            .collect::<Vec<_>>();
        let local_completion = completion_for_site_iter(
            identities,
            &gaps_by_site,
            std::iter::once(call.call)
                .chain(std::iter::once(call.callee))
                .chain(call.receiver.into_iter().map(|slot| index.slot(slot).site))
                .chain(
                    arguments
                        .iter()
                        .map(|argument| index.slot(argument.value).site),
                ),
        );
        let completion = local_completion.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(applicability_reason),
        ]));
        call_obligations.push(LoweredCallApplicabilityObligation::new(
            call_semantic,
            identities.semantic(reference_semantic_identity(call.callee)),
            call.receiver
                .map(|slot| identities.semantic(type_slot_semantic_identity(slot))),
            identities.semantic(type_slot_semantic_identity(call.result)),
            argument_slots,
            eligible_rules_by_call
                .remove(&call.call)
                .unwrap_or_default(),
            call.explicit_type_argument_count,
            applicability_reason,
            completion,
        ));
    }
    assert!(
        eligible_rules_by_call.is_empty(),
        "engine rule eligibility must name an emitted call obligation: {eligible_rules_by_call:?}"
    );

    let parameters_by_callable = normalized_callable_parameters(facts, &index);
    let mut signature_headers = facts.callable_signatures.clone();
    signature_headers.sort_unstable_by_key(|header| header.callable);
    let mut callable_signatures = Vec::with_capacity(signature_headers.len());
    for header in signature_headers {
        let callable = header.callable;
        let parameters = parameters_by_callable
            .get(&callable)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let lowered_parameters = parameters
            .iter()
            .map(|parameter| {
                LoweredCallableParameterProperty::new(
                    parameter.ordinal,
                    identities.semantic(definition_semantic_identity(parameter.parameter)),
                    identities.semantic(type_slot_semantic_identity(parameter.value_type)),
                    parameter.repeated,
                )
            })
            .collect::<Vec<_>>();
        let completion = completion_for_site_iter(
            identities,
            &gaps_by_site,
            std::iter::once(callable).chain(parameters.iter().map(|row| row.parameter)),
        );
        callable_signatures.push(LoweredCallableSignatureProperty::new(
            identities.semantic(definition_semantic_identity(callable)),
            header.type_parameter_count,
            lowered_parameters,
            completion,
        ));
    }

    LoweredTypedFragment::new(
        fragment,
        language,
        frontiers,
        transfers,
        intrinsic_seeds,
        projections,
        qualified_routes,
        declaration_types,
        declaration_visibilities,
        member_scopes,
        member_owners,
        construction_requirements,
        supertypes,
        property_gaps,
        call_obligations,
        callable_signatures,
    )
}

fn lower_member_scope_properties(
    identities: &mut ResolutionIdentityCatalogBuilder,
    index: &TypedFactIndex<'_>,
) -> Vec<LoweredMemberScopeProperty> {
    let mut properties = index
        .type_member_scopes()
        .into_iter()
        .map(|(declaration, scope)| {
            LoweredMemberScopeProperty::new(
                identities.semantic(definition_semantic_identity(declaration)),
                identities.node(scope_head_node_identity(scope)),
            )
        })
        .collect::<Vec<_>>();
    properties.sort_unstable();
    properties
}

fn lower_declaration_visibility_properties(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    index: &TypedFactIndex<'_>,
) -> Vec<LoweredDeclarationVisibilityProperty> {
    let mut eligible = HashSet::default();
    for eligibility in &facts.visibility_eligibilities {
        index.definition_identifier(eligibility.declaration);
        assert!(
            eligible.insert(eligibility.declaration),
            "one visibility eligibility row per declaration is required: {eligibility:?}"
        );
    }
    let mut seen = HashSet::default();
    let mut properties = Vec::with_capacity(facts.declaration_visibilities.len());
    for &fact in &facts.declaration_visibilities {
        assert!(
            seen.insert(fact.declaration),
            "one declaration-visibility row per definition is required: {fact:?}"
        );
        assert!(
            eligible.contains(&fact.declaration),
            "visibility row must name a supported type, callable, constructor, or field: {fact:?}"
        );
        properties.push(LoweredDeclarationVisibilityProperty::new(
            identities.semantic(definition_semantic_identity(fact.declaration)),
            fact.visibility,
        ));
    }

    if language == Language::Java {
        assert_eq!(
            seen, eligible,
            "Java visibility inventory must cover every supported declaration exactly once"
        );
        let mut visibility_gap_counts = HashMap::default();
        for gap in facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
        {
            assert!(
                eligible.contains(&gap.site),
                "Java visibility gap must be owned by its exact supported declaration: {gap:?}"
            );
            *visibility_gap_counts.entry(gap.site).or_insert(0_usize) += 1;
        }
        for fact in &facts.declaration_visibilities {
            let gap_count = visibility_gap_counts
                .get(&fact.declaration)
                .copied()
                .unwrap_or_default();
            if fact.visibility == DeclaredVisibility::Public {
                assert_eq!(
                    gap_count, 0,
                    "public Java declaration cannot retain a visibility gap: {fact:?}"
                );
            } else {
                assert_eq!(
                    gap_count, 1,
                    "non-public Java declaration requires one exact visibility gap: {fact:?}"
                );
            }
        }
    }

    properties.sort_unstable();
    properties
}

fn lower_definition_properties_with_index(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    index: &TypedFactIndex<'_>,
    member_scopes: &[LoweredMemberScopeProperty],
) -> LoweredDefinitionProperties {
    let declaration_visibilities =
        lower_declaration_visibility_properties(identities, language, facts, index);
    let member_scope_by_definition = member_scopes
        .iter()
        .map(|property| (property.definition, property.scope_head))
        .collect::<HashMap<_, _>>();
    assert_eq!(
        member_scope_by_definition.len(),
        member_scopes.len(),
        "one member scope per type definition is required"
    );

    let mut seen_member_owners = HashSet::default();
    let mut member_owners = Vec::with_capacity(facts.member_owners.len());
    for &fact in &facts.member_owners {
        assert!(
            seen_member_owners.insert(fact),
            "duplicate member-owner property: {fact:?}"
        );
        validate_member_owner(fact, index);
        let owner_definition = identities.semantic(definition_semantic_identity(fact.owner));
        let owner_scope_head = *member_scope_by_definition
            .get(&owner_definition)
            .unwrap_or_else(|| panic!("member owner {} has no type-body scope", fact.owner));
        member_owners.push(LoweredMemberOwnerProperty::new(
            identities.semantic(definition_semantic_identity(fact.member)),
            owner_definition,
            owner_scope_head,
            fact.kind,
            fact.access,
            fact.qualifier_compatibility,
        ));
    }
    member_owners.sort_by_key(member_owner_sort_key);

    let mut seen_requirements = HashSet::default();
    let mut construction_requirements = Vec::with_capacity(facts.construction_requirements.len());
    for &fact in &facts.construction_requirements {
        assert!(
            seen_requirements.insert(fact),
            "duplicate construction requirement: {fact:?}"
        );
        validate_construction_requirement(fact, index, facts);
        construction_requirements.push(LoweredConstructionRequirementProperty::new(
            identities.semantic(definition_semantic_identity(fact.constructed_type)),
            identities.semantic(definition_semantic_identity(fact.required_owner)),
            fact.kind,
        ));
    }
    construction_requirements.sort_by_key(construction_requirement_sort_key);

    let mut seen_supertypes = HashSet::default();
    let mut supertypes = Vec::with_capacity(facts.supertypes.len());
    for &fact in &facts.supertypes {
        assert!(
            seen_supertypes.insert(fact),
            "duplicate supertype property: {fact:?}"
        );
        validate_supertype(fact, index, facts);
        supertypes.push(LoweredSupertypeProperty::new(
            identities.semantic(definition_semantic_identity(fact.subtype)),
            identities.semantic(reference_semantic_identity(fact.supertype_reference)),
            identities.semantic(type_slot_semantic_identity(fact.supertype_slot)),
            fact.kind,
        ));
    }
    supertypes.sort_by_key(supertype_sort_key);

    let mut source_member_owner = HashMap::default();
    for &owner in &facts.member_owners {
        assert!(
            source_member_owner.insert(owner.member, owner).is_none(),
            "one member-owner property per declaration is required"
        );
    }
    let mut property_gaps = Vec::new();
    for gap in &facts.gaps {
        let owner = match gap.kind {
            ResolutionGapKind::ImplicitConstructor => {
                validate_type_definition(gap.site, index);
                Some(gap.site)
            }
            ResolutionGapKind::UnsupportedHierarchyTraversal => {
                Some(hierarchy_gap_owner(gap.site, index, facts))
            }
            ResolutionGapKind::UnsupportedVisibility => {
                if index.site(gap.site).kind == ResolutionSiteKind::TypeDeclaration {
                    validate_type_definition(gap.site, index);
                } else {
                    let owner = source_member_owner
                        .get(&gap.site)
                        .copied()
                        .unwrap_or_else(|| {
                            panic!(
                                "member visibility gap {} has no exact member-owner property",
                                gap.site
                            )
                        });
                    validate_member_owner(owner, index);
                }
                Some(gap.site)
            }
            _ => None,
        };
        let Some(owner) = owner else {
            continue;
        };
        let reason_semantic = identities.semantic(gap_reason_semantic_identity(
            gap.site,
            LoweringGapOrigin::Extracted(gap.kind),
        ));
        for frontier in index.type_frontiers(identities, gap.site) {
            property_gaps.push(LoweredDefinitionPropertyGap::new(
                identities.semantic(definition_semantic_identity(owner)),
                gap.site,
                gap.kind,
                frontier,
                reason_semantic,
            ));
        }
    }
    property_gaps.sort_by_key(property_gap_sort_key);

    LoweredDefinitionProperties {
        declaration_visibilities,
        member_owners,
        construction_requirements,
        supertypes,
        property_gaps,
    }
}

struct TypedFactIndex<'facts> {
    names: HashMap<ResolutionNameId, &'facts str>,
    scopes: HashMap<ResolutionScopeId, ResolutionScopeFact>,
    sites: HashMap<ResolutionSiteId, ResolutionSiteFact>,
    identifiers: HashMap<ResolutionSiteId, &'facts PositionedIdentifierFact>,
    slots: HashMap<ResolutionTypeSlotId, ResolutionTypeSlotFact>,
    slots_by_site: HashMap<ResolutionSiteId, Vec<ResolutionTypeSlotId>>,
    type_body_scope_by_owner: HashMap<ResolutionSiteId, ResolutionScopeId>,
}

impl<'facts> TypedFactIndex<'facts> {
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
            assert!(
                scope.start_byte <= scope.end_byte,
                "invalid scope: {scope:?}"
            );
            assert!(
                scopes.insert(scope.id, scope).is_none(),
                "duplicate resolution scope ID {}",
                scope.id
            );
        }

        let mut sites = HashMap::default();
        for &site in &facts.sites {
            assert!(site.start_byte <= site.end_byte, "invalid site: {site:?}");
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

        for scope in scopes.values() {
            if let Some(owner) = scope.owner {
                assert!(
                    sites.contains_key(&owner),
                    "scope {} names unknown owner {owner}",
                    scope.id
                );
            }
        }

        let mut identifiers = HashMap::default();
        for identifier in &facts.identifiers {
            assert!(sites.contains_key(&identifier.site));
            assert!(names.contains_key(&identifier.name));
            assert!(
                identifiers.insert(identifier.site, identifier).is_none(),
                "one positioned identifier per semantic site is required: {identifier:?}"
            );
        }

        let mut slots = HashMap::default();
        let mut slots_by_site: HashMap<_, Vec<_>> = HashMap::default();
        for &slot in &facts.type_slots {
            assert!(sites.contains_key(&slot.site));
            assert!(
                slots.insert(slot.id, slot).is_none(),
                "duplicate resolution type slot {}",
                slot.id
            );
            slots_by_site.entry(slot.site).or_default().push(slot.id);
        }
        for values in slots_by_site.values_mut() {
            values.sort_unstable();
        }

        for identifier in identifiers.values() {
            if let Some(qualifier) = identifier.qualifier {
                assert!(
                    slots.contains_key(&qualifier),
                    "identifier qualifier names unknown type slot {qualifier}"
                );
            }
        }
        for gap in &facts.gaps {
            assert!(
                sites.contains_key(&gap.site),
                "gap names unknown site: {gap:?}"
            );
        }

        let mut type_body_scope_by_owner = HashMap::default();
        for scope in scopes.values() {
            if scope.kind != ResolutionScopeKind::TypeBody {
                continue;
            }
            let owner = scope
                .owner
                .expect("a type-body scope requires its type declaration owner");
            let owner_site = sites.get(&owner).expect("scope owner was validated");
            assert_eq!(
                owner_site.kind,
                ResolutionSiteKind::TypeDeclaration,
                "type-body scope owner must be a type declaration"
            );
            assert!(
                type_body_scope_by_owner.insert(owner, scope.id).is_none(),
                "one type-body scope per type declaration is required"
            );
        }

        Self {
            names,
            scopes,
            sites,
            identifiers,
            slots,
            slots_by_site,
            type_body_scope_by_owner,
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

    fn validate_remaining_typed_relations(&self, facts: &FileResolutionFacts) {
        let mut seen_binders = HashSet::default();
        for binder in &facts.binders {
            assert!(seen_binders.insert(*binder), "duplicate binder: {binder:?}");
            let declaration = self.definition_identifier(binder.declaration);
            assert!(self.scopes.contains_key(&binder.scope));
            assert!(binder.activation_start <= binder.activation_end);
            assert!(binder_namespace_is_declared(
                facts,
                *binder,
                declaration.namespace
            ));
        }

        let mut calls = HashMap::default();
        for call in &facts.calls {
            assert_eq!(self.site(call.call).kind, ResolutionSiteKind::Call);
            let callee = self.site(call.callee);
            assert!(
                matches!(
                    callee.kind,
                    ResolutionSiteKind::CallableReference
                        | ResolutionSiteKind::ConstructorReference
                        | ResolutionSiteKind::MemberReference
                        | ResolutionSiteKind::UnsupportedExpression
                ),
                "invalid call callee site: {call:?}, {callee:?}"
            );
            if !matches!(callee.kind, ResolutionSiteKind::UnsupportedExpression) {
                self.reference_identifier(call.callee);
                assert!(
                    facts.binding_projections.iter().any(|projection| {
                        projection.reference == call.callee && projection.output == call.result
                    }),
                    "supported call lacks its result projection: {call:?}"
                );
            }
            let result = self.slot(call.result);
            assert_eq!(result.site, call.call);
            assert_eq!(result.role, ResolutionTypeSlotRole::CallResult);
            if let Some(receiver) = call.receiver {
                let receiver = self.slot(receiver);
                assert_eq!(receiver.site, call.call);
                assert_eq!(receiver.role, ResolutionTypeSlotRole::Receiver);
            }
            assert!(
                calls.insert(call.call, call).is_none(),
                "duplicate call site"
            );
        }

        let mut call_arguments = HashSet::default();
        for argument in &facts.call_arguments {
            let call = calls
                .get(&argument.call)
                .unwrap_or_else(|| panic!("argument names unknown call: {argument:?}"));
            let value = self.slot(argument.value);
            assert_eq!(value.site, call.call);
            assert_eq!(value.role, ResolutionTypeSlotRole::Argument);
            assert!(
                call_arguments.insert((argument.call, argument.ordinal)),
                "duplicate call argument ordinal: {argument:?}"
            );
        }

        let mut parameters = HashSet::default();
        let callable_definitions = self
            .callable_definitions()
            .into_iter()
            .collect::<HashSet<_>>();
        let mut signature_headers = HashSet::default();
        for header in &facts.callable_signatures {
            let callable = self.site(header.callable);
            assert!(matches!(
                callable.kind,
                ResolutionSiteKind::CallableDeclaration
                    | ResolutionSiteKind::ConstructorDeclaration
            ));
            self.definition_identifier(header.callable);
            assert!(
                signature_headers.insert(header.callable),
                "duplicate callable signature header: {header:?}"
            );
        }
        assert_eq!(
            signature_headers, callable_definitions,
            "every callable definition requires exactly one signature header"
        );
        for parameter in &facts.callable_parameters {
            let callable = self.site(parameter.callable);
            assert!(matches!(
                callable.kind,
                ResolutionSiteKind::CallableDeclaration
                    | ResolutionSiteKind::ConstructorDeclaration
            ));
            self.definition_identifier(parameter.callable);
            let parameter_site = self.site(parameter.parameter);
            assert_eq!(parameter_site.kind, ResolutionSiteKind::ValueDeclaration);
            self.definition_identifier(parameter.parameter);
            let value_type = self.slot(parameter.value_type);
            assert_eq!(value_type.site, parameter.parameter);
            assert_eq!(value_type.role, ResolutionTypeSlotRole::DeclaredValue);
            assert!(
                facts.declaration_type_slots.iter().any(|property| {
                    property.declaration == parameter.parameter
                        && property.slot == parameter.value_type
                        && property.role == DeclarationTypeRole::Parameter
                }),
                "callable parameter lacks its declared type property: {parameter:?}"
            );
            assert!(
                parameters.insert((parameter.callable, parameter.ordinal)),
                "duplicate callable parameter ordinal: {parameter:?}"
            );
            assert!(
                signature_headers.contains(&parameter.callable),
                "callable parameter lacks its signature header: {parameter:?}"
            );
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

    fn slot(&self, id: ResolutionTypeSlotId) -> ResolutionTypeSlotFact {
        *self
            .slots
            .get(&id)
            .unwrap_or_else(|| panic!("unknown resolution type slot {id}"))
    }

    fn identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        self.identifiers
            .get(&site)
            .copied()
            .unwrap_or_else(|| panic!("site {site} has no positioned identifier"))
    }

    fn definition_identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        let identifier = self.identifier(site);
        assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
        identifier
    }

    fn reference_identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        let identifier = self.identifier(site);
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        identifier
    }

    fn type_frontiers(
        &self,
        identities: &mut ResolutionIdentityCatalogBuilder,
        site: ResolutionSiteId,
    ) -> Vec<SemanticId> {
        self.slots_by_site
            .get(&site)
            .map(|slots| {
                slots
                    .iter()
                    .map(|&slot| identities.semantic(type_slot_semantic_identity(slot)))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![identities.semantic(site_type_frontier_semantic_identity(site))]
            })
    }

    fn type_member_scopes(&self) -> Vec<(ResolutionSiteId, ResolutionScopeId)> {
        let mut scopes = self
            .type_body_scope_by_owner
            .iter()
            .map(|(&owner, &scope)| (owner, scope))
            .collect::<Vec<_>>();
        scopes.sort_unstable();
        for &(owner, _) in &scopes {
            validate_type_definition(owner, self);
        }
        scopes
    }

    fn callable_definitions(&self) -> Vec<ResolutionSiteId> {
        let mut definitions = self
            .identifiers
            .values()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .filter_map(|identifier| {
                matches!(
                    self.site(identifier.site).kind,
                    ResolutionSiteKind::CallableDeclaration
                        | ResolutionSiteKind::ConstructorDeclaration
                )
                .then_some(identifier.site)
            })
            .collect::<Vec<_>>();
        definitions.sort_unstable();
        definitions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedOutputProducerFamily {
    Transfer,
    Intrinsic,
    Projection,
}

/// A typed slot has one affirmative value producer.
///
/// Declaration, call, parameter, and property rows may all refer to that
/// output, but no current relation defines merge semantics between two
/// intrinsic seeds, projections, or transfers. Rejecting even same-family
/// duplicates keeps a malformed producer graph from depending on row order.
fn validate_output_producers(facts: &FileResolutionFacts, index: &TypedFactIndex<'_>) {
    let mut producers = HashMap::default();
    let mut register = |slot: ResolutionTypeSlotId, family: TypedOutputProducerFamily| {
        index.slot(slot);
        if let Some(previous) = producers.insert(slot, family) {
            panic!("typed slot {slot} has multiple output producers: {previous:?} and {family:?}");
        }
    };
    for transfer in &facts.type_transfers {
        register(transfer.output, TypedOutputProducerFamily::Transfer);
    }
    for intrinsic in &facts.intrinsic_type_seeds {
        register(intrinsic.output, TypedOutputProducerFamily::Intrinsic);
    }
    for projection in &facts.binding_projections {
        register(projection.output, TypedOutputProducerFamily::Projection);
    }
}

fn normalized_call_arguments<'facts>(
    facts: &'facts FileResolutionFacts,
    index: &TypedFactIndex<'_>,
) -> HashMap<ResolutionSiteId, Vec<&'facts ResolutionCallArgumentFact>> {
    let mut by_call: HashMap<_, Vec<_>> = HashMap::default();
    for argument in &facts.call_arguments {
        index.slot(argument.value);
        by_call.entry(argument.call).or_default().push(argument);
    }
    for (&call, arguments) in &mut by_call {
        arguments.sort_unstable_by_key(|argument| argument.ordinal);
        for (expected, argument) in arguments.iter().enumerate() {
            assert_eq!(
                usize::try_from(argument.ordinal).expect("u32 ordinal fits usize"),
                expected,
                "call {call} argument ordinals must be contiguous from zero"
            );
        }
    }
    by_call
}

fn normalized_callable_parameters<'facts>(
    facts: &'facts FileResolutionFacts,
    index: &TypedFactIndex<'_>,
) -> HashMap<ResolutionSiteId, Vec<&'facts ResolutionCallableParameterFact>> {
    let mut by_callable: HashMap<_, Vec<_>> = HashMap::default();
    for parameter in &facts.callable_parameters {
        index.slot(parameter.value_type);
        by_callable
            .entry(parameter.callable)
            .or_default()
            .push(parameter);
    }
    for (&callable, parameters) in &mut by_callable {
        parameters.sort_unstable_by_key(|parameter| parameter.ordinal);
        let mut definitions = HashSet::default();
        for (expected, parameter) in parameters.iter().enumerate() {
            assert_eq!(
                usize::try_from(parameter.ordinal).expect("u32 ordinal fits usize"),
                expected,
                "callable {callable} parameter ordinals must be contiguous from zero"
            );
            assert!(
                definitions.insert(parameter.parameter),
                "callable {callable} repeats parameter definition {}",
                parameter.parameter
            );
            if parameter.repeated {
                assert_eq!(
                    expected + 1,
                    parameters.len(),
                    "repeated parameter must be last in callable {callable}"
                );
            }
        }
    }
    by_callable
}

fn validate_transfer_roles(
    fact: ResolutionTypeTransferFact,
    input: ResolutionTypeSlotRole,
    output: ResolutionTypeSlotRole,
) {
    let expected_output = transfer_output_role(fact.kind);
    assert_eq!(
        output, expected_output,
        "type-transfer kind and output role disagree: {fact:?}"
    );
    if fact.kind == ResolutionTypeTransferKind::DeclaredType {
        assert_eq!(
            input,
            ResolutionTypeSlotRole::TargetTypeIdentity,
            "declared-type transfer input must retain a type object: {fact:?}"
        );
    }
}

const fn transfer_output_role(kind: ResolutionTypeTransferKind) -> ResolutionTypeSlotRole {
    match kind {
        ResolutionTypeTransferKind::DeclaredType => ResolutionTypeSlotRole::DeclaredValue,
        ResolutionTypeTransferKind::Assignment => ResolutionTypeSlotRole::AssignmentValue,
        ResolutionTypeTransferKind::Construction => ResolutionTypeSlotRole::CallResult,
        ResolutionTypeTransferKind::Receiver => ResolutionTypeSlotRole::Receiver,
        ResolutionTypeTransferKind::Argument => ResolutionTypeSlotRole::Argument,
        ResolutionTypeTransferKind::Return => ResolutionTypeSlotRole::ReturnValue,
    }
}

const fn lower_value_transform(
    transform: ResolutionTypeTransferValueTransform,
) -> TypeTransferValueTransform {
    match transform {
        ResolutionTypeTransferValueTransform::Preserve => TypeTransferValueTransform::Preserve,
        ResolutionTypeTransferValueTransform::ToRuntime { addressable } => {
            TypeTransferValueTransform::ToRuntime { addressable }
        }
        ResolutionTypeTransferValueTransform::ToNoValue => TypeTransferValueTransform::ToNoValue,
    }
}

fn validate_projection(
    fact: BindingProjectionFact,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) {
    let reference = index.reference_identifier(fact.reference);
    let output = index.slot(fact.output);
    let (namespace, role) = projection_contract(fact.kind);
    assert_eq!(reference.namespace, namespace);
    assert_eq!(output.role, role);
    if fact.kind == BindingProjectionKind::TargetConstructorOwnerType {
        let qualifier = reference
            .qualifier
            .expect("constructor projection requires its constructed-type qualifier");
        assert_eq!(
            index.slot(qualifier).role,
            ResolutionTypeSlotRole::TargetTypeIdentity,
            "constructor projection qualifier must retain a type object"
        );
    }
    if matches!(
        fact.kind,
        BindingProjectionKind::TargetCallableResultType
            | BindingProjectionKind::TargetConstructorOwnerType
    ) {
        assert!(
            facts
                .calls
                .iter()
                .any(|call| { call.callee == fact.reference && call.result == fact.output }),
            "call-result projection is not attached to its call: {fact:?}"
        );
    }
}

const fn projection_contract(
    kind: BindingProjectionKind,
) -> (ResolutionNamespace, ResolutionTypeSlotRole) {
    match kind {
        BindingProjectionKind::TargetTypeIdentity => (
            ResolutionNamespace::Type,
            ResolutionTypeSlotRole::TargetTypeIdentity,
        ),
        BindingProjectionKind::TargetDeclaredValueType => (
            ResolutionNamespace::Value,
            ResolutionTypeSlotRole::ExpressionValue,
        ),
        BindingProjectionKind::TargetCallableResultType => (
            ResolutionNamespace::Callable,
            ResolutionTypeSlotRole::CallResult,
        ),
        BindingProjectionKind::TargetConstructorOwnerType => (
            ResolutionNamespace::Constructor,
            ResolutionTypeSlotRole::CallResult,
        ),
        BindingProjectionKind::TargetTypeOrDeclaredValueType => (
            ResolutionNamespace::TypeOrValue,
            ResolutionTypeSlotRole::ExpressionValue,
        ),
    }
}

fn validate_declaration_type(fact: DeclarationTypeSlotFact, index: &TypedFactIndex<'_>) {
    let declaration = index.site(fact.declaration);
    index.definition_identifier(fact.declaration);
    let slot = index.slot(fact.slot);
    assert_eq!(slot.site, fact.declaration);
    assert_eq!(slot.role, ResolutionTypeSlotRole::DeclaredValue);
    match fact.role {
        DeclarationTypeRole::Value | DeclarationTypeRole::Parameter => {
            assert_eq!(declaration.kind, ResolutionSiteKind::ValueDeclaration);
        }
        DeclarationTypeRole::Return => {
            assert_eq!(declaration.kind, ResolutionSiteKind::CallableDeclaration);
        }
    }
}

fn validate_member_owner(fact: ResolutionMemberOwnerFact, index: &TypedFactIndex<'_>) {
    validate_type_definition(fact.owner, index);
    let member = index.site(fact.member);
    let owner_scope = index
        .type_body_scope_by_owner
        .get(&fact.owner)
        .copied()
        .unwrap_or_else(|| panic!("member owner {} has no type-body scope", fact.owner));
    assert_eq!(
        member.scope, owner_scope,
        "member declaration must be positioned in its owner's type-body scope"
    );
    let identifier = index.definition_identifier(fact.member);
    let (site_kind, namespace) = match fact.kind {
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
    assert_eq!(member.kind, site_kind);
    assert_eq!(identifier.namespace, namespace);
}

fn validate_construction_requirement(
    fact: ResolutionConstructionRequirementFact,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) {
    validate_type_definition(fact.constructed_type, index);
    validate_type_definition(fact.required_owner, index);
    assert!(
        facts.member_owners.iter().any(|owner| {
            owner.member == fact.constructed_type
                && owner.owner == fact.required_owner
                && owner.kind == ResolutionMemberKind::NestedType
                && owner.access == ResolutionMemberAccess::Type
        }),
        "construction requirement is not linked to nested-type ownership: {fact:?}"
    );
}

fn validate_supertype(
    fact: ResolutionSupertypeFact,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) {
    validate_type_definition(fact.subtype, index);
    let reference = index.reference_identifier(fact.supertype_reference);
    assert_eq!(reference.namespace, ResolutionNamespace::Type);
    let slot = index.slot(fact.supertype_slot);
    assert_eq!(slot.site, fact.supertype_reference);
    assert_eq!(slot.role, ResolutionTypeSlotRole::TargetTypeIdentity);
    assert!(
        facts.binding_projections.iter().any(|projection| {
            projection.reference == fact.supertype_reference
                && projection.output == fact.supertype_slot
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }),
        "supertype reference lacks its target-independent type projection: {fact:?}"
    );
}

fn validate_type_definition(site: ResolutionSiteId, index: &TypedFactIndex<'_>) {
    assert_eq!(index.site(site).kind, ResolutionSiteKind::TypeDeclaration);
    assert_eq!(
        index.definition_identifier(site).namespace,
        ResolutionNamespace::Type
    );
}

fn hierarchy_gap_owner(
    site: ResolutionSiteId,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) -> ResolutionSiteId {
    if index.site(site).kind == ResolutionSiteKind::TypeDeclaration {
        validate_type_definition(site, index);
        return site;
    }
    let mut owners = facts
        .supertypes
        .iter()
        .filter(|supertype| supertype.supertype_reference == site)
        .map(|supertype| supertype.subtype);
    let owner = owners
        .next()
        .unwrap_or_else(|| panic!("hierarchy gap at {site} has no owning subtype property"));
    assert!(
        owners.next().is_none(),
        "hierarchy gap at {site} has multiple owning subtype properties"
    );
    validate_type_definition(owner, index);
    owner
}

fn gaps_by_site(facts: &FileResolutionFacts) -> HashMap<ResolutionSiteId, Vec<ResolutionGapKind>> {
    let mut gaps: HashMap<_, Vec<_>> = HashMap::default();
    let mut seen = HashSet::default();
    for gap in &facts.gaps {
        assert!(seen.insert(*gap), "duplicate resolution gap: {gap:?}");
        gaps.entry(gap.site).or_default().push(gap.kind);
    }
    for kinds in gaps.values_mut() {
        kinds.sort_unstable();
    }
    gaps
}

fn completion_for_sites<const N: usize>(
    identities: &mut ResolutionIdentityCatalogBuilder,
    gaps_by_site: &HashMap<ResolutionSiteId, Vec<ResolutionGapKind>>,
    sites: [ResolutionSiteId; N],
) -> ResolutionCompletion {
    completion_for_site_iter(identities, gaps_by_site, sites)
}

fn completion_for_site_iter(
    identities: &mut ResolutionIdentityCatalogBuilder,
    gaps_by_site: &HashMap<ResolutionSiteId, Vec<ResolutionGapKind>>,
    sites: impl IntoIterator<Item = ResolutionSiteId>,
) -> ResolutionCompletion {
    let mut reasons = Vec::new();
    for site in sites {
        for &kind in gaps_by_site.get(&site).into_iter().flatten() {
            // Declaration visibility is a closed-world property relation. It
            // is attached to the final surviving candidate, never to an
            // unrelated typed transfer, call, or signature operand.
            if kind != ResolutionGapKind::UnsupportedVisibility {
                reasons.push(ResolutionIncompleteReason::UnsupportedSemantic(
                    identities.semantic(gap_reason_semantic_identity(
                        site,
                        LoweringGapOrigin::Extracted(kind),
                    )),
                ));
            }
        }
    }
    if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    }
}

fn assert_declared_frontier(
    inventory: &HashMap<SemanticId, ResolutionTypeSlotRole>,
    slot: SemanticId,
    relation: &'static str,
) -> ResolutionTypeSlotRole {
    inventory
        .get(&slot)
        .copied()
        .unwrap_or_else(|| panic!("{relation} names undeclared typed frontier {slot:?}"))
}

fn assert_persistable_typed_completion(completion: &ResolutionCompletion, relation: &'static str) {
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        assert!(
            !reasons.is_empty(),
            "{relation} incomplete completion requires at least one reason"
        );
        assert!(
            (1..reasons.len()).all(|index| {
                reasons
                    .get(index - 1)
                    .expect("completion reason predecessor is present")
                    < reasons.get(index).expect("completion reason is present")
            }),
            "{relation} incomplete reasons must be strictly sorted and unique"
        );
    }
    assert!(
        !completion.contains_reason(ResolutionIncompleteReason::Cancelled),
        "{relation} completion cannot persist operation-local cancellation"
    );
}

fn assert_intrinsic_seed_matches_role(seed: &LoweredIntrinsicSeed, role: ResolutionTypeSlotRole) {
    match role {
        ResolutionTypeSlotRole::TargetTypeIdentity => assert!(
            matches!(
                seed.frontier.possible_values(),
                [ResolutionSlotValue::TypeObject(_)]
            ),
            "TargetTypeIdentity intrinsic seed must contain exactly one TypeObject value"
        ),
        ResolutionTypeSlotRole::ExpressionValue => assert!(
            matches!(
                seed.frontier.possible_values(),
                [ResolutionSlotValue::Runtime {
                    addressable: false,
                    ..
                }]
            ),
            "ExpressionValue intrinsic seed must contain exactly one non-addressable Runtime value"
        ),
        unsupported => {
            assert!(
                seed.frontier.possible_values().is_empty(),
                "unsupported intrinsic seed role {unsupported:?} must contain no values"
            );
            assert!(
                matches!(
                    seed.frontier.completion(),
                    ResolutionCompletion::Incomplete(_)
                ),
                "unsupported intrinsic seed role {unsupported:?} must remain incomplete"
            );
        }
    }
}

fn assert_source_lowerable_qualified_routes(routes: &[LoweredQualifiedSeededRoute]) {
    let mut routes_by_projection: HashMap<_, Vec<_>> = HashMap::default();
    for route in routes {
        routes_by_projection
            .entry((
                route.reference,
                route.projection_output_slot,
                route.projection_kind,
            ))
            .or_default()
            .push(route);
    }

    for ((reference, output_slot, kind), projection_routes) in routes_by_projection {
        let mut actual_shape = projection_routes
            .iter()
            .map(|route| (route.precedence_ordinal, route.namespace))
            .collect::<Vec<_>>();
        actual_shape.sort_unstable();
        let expected_shape = lookup_routes(projection_contract(kind).0);
        assert_eq!(
            actual_shape.as_slice(),
            expected_shape,
            "qualified routes for projection ({reference:?}, {output_slot:?}, {kind:?}) must have the exact source-lowerable namespace and precedence shape"
        );

        let first = projection_routes[0];
        assert!(
            projection_routes.iter().all(|route| {
                route.qualifier_slot == first.qualifier_slot
                    && route.coarse_gap_reason == first.coarse_gap_reason
            }),
            "qualified routes for one projection must share their qualifier and coarse gap reason"
        );
    }
}

fn validate_lowered_output_producers(
    transfers: &[LoweredTypeTransfer],
    intrinsic_seeds: &[LoweredIntrinsicSeed],
    projections: &[LoweredBindingProjection],
) {
    let mut producers = HashMap::default();
    let mut register = |slot: SemanticId, family: TypedOutputProducerFamily| {
        if let Some(previous) = producers.insert(slot, family) {
            panic!(
                "typed frontier {slot:?} has multiple output producers: {previous:?} and {family:?}"
            );
        }
    };
    for transfer in transfers {
        register(
            transfer.rule.target_slot(),
            TypedOutputProducerFamily::Transfer,
        );
    }
    for seed in intrinsic_seeds {
        register(seed.frontier.slot(), TypedOutputProducerFamily::Intrinsic);
    }
    for projection in projections {
        register(
            projection.output_slot,
            TypedOutputProducerFamily::Projection,
        );
    }
}

fn assert_unique_lowered_rows(fragment: &LoweredTypedFragment) {
    let mut transfer_semantics = HashSet::default();
    for transfer in &fragment.transfers {
        assert!(
            transfer_semantics.insert(transfer.rule.semantic()),
            "type-transfer rule semantic must be unique within a fragment"
        );
    }
    assert!(
        fragment
            .transfers
            .windows(2)
            .all(|pair| transfer_sort_key(&pair[0]) != transfer_sort_key(&pair[1])),
        "duplicate lowered type transfer"
    );
    assert!(
        fragment
            .intrinsic_seeds
            .windows(2)
            .all(|pair| intrinsic_sort_key(&pair[0]) != intrinsic_sort_key(&pair[1])),
        "duplicate lowered intrinsic seed"
    );

    let mut projection_references = HashSet::default();
    for projection in &fragment.projections {
        assert!(
            projection_references.insert(projection.reference),
            "one binding projection per reference is required"
        );
    }
    let mut qualified_route_ordinals = HashSet::default();
    let mut coarse_gap_reason_owners = HashMap::default();
    for route in &fragment.qualified_routes {
        assert!(
            qualified_route_ordinals.insert((route.reference, route.precedence_ordinal)),
            "qualified route (reference, precedence ordinal) must be unique"
        );
        if let Some(owner) =
            coarse_gap_reason_owners.insert(route.coarse_gap_reason, route.reference)
        {
            assert_eq!(
                owner, route.reference,
                "qualified-route coarse gap reason may belong to only one reference per fragment"
            );
        }
    }
    assert!(
        fragment
            .qualified_routes
            .windows(2)
            .all(|pair| qualified_route_sort_key(&pair[0]) != qualified_route_sort_key(&pair[1])),
        "duplicate lowered qualified seeded route"
    );

    let mut declaration_role_keys = HashSet::default();
    for property in &fragment.declaration_types {
        assert!(
            declaration_role_keys.insert((property.definition, property.role)),
            "one declaration type slot per (definition, role) is required"
        );
    }

    assert!(
        fragment
            .declaration_visibilities
            .windows(2)
            .all(|pair| pair[0].definition != pair[1].definition),
        "one lowered declaration-visibility property per definition is required"
    );

    let mut member_scope_definitions = HashSet::default();
    let mut member_scope_heads = HashSet::default();
    for property in &fragment.member_scopes {
        assert!(
            member_scope_definitions.insert(property.definition),
            "one member scope per type definition is required"
        );
        assert!(
            member_scope_heads.insert(property.scope_head),
            "member-scope head may belong to only one type definition"
        );
    }
    assert!(
        fragment
            .member_owners
            .windows(2)
            .all(|pair| member_owner_sort_key(&pair[0]) != member_owner_sort_key(&pair[1])),
        "duplicate lowered member-owner property"
    );
    assert!(
        fragment.construction_requirements.windows(2).all(|pair| {
            construction_requirement_sort_key(&pair[0])
                != construction_requirement_sort_key(&pair[1])
        }),
        "duplicate lowered construction requirement"
    );
    assert!(
        fragment
            .supertypes
            .windows(2)
            .all(|pair| supertype_sort_key(&pair[0]) != supertype_sort_key(&pair[1])),
        "duplicate lowered supertype property"
    );
    assert!(
        fragment
            .property_gaps
            .windows(2)
            .all(|pair| property_gap_sort_key(&pair[0]) != property_gap_sort_key(&pair[1])),
        "duplicate lowered definition property gap"
    );
    let mut property_gap_identities = HashSet::default();
    let mut property_gap_owners = HashMap::default();
    for gap in &fragment.property_gaps {
        assert!(
            property_gap_identities.insert((gap.definition, gap.reason_semantic, gap.frontier)),
            "definition property-gap SQL identity must be unique"
        );
        if let Some(owner) = property_gap_owners.insert(
            (gap.source_site, gap.kind, gap.reason_semantic),
            gap.definition,
        ) {
            assert_eq!(
                owner, gap.definition,
                "one definition owner per property-gap source provenance is required"
            );
        }
    }

    let mut calls = HashSet::default();
    let mut callee_references = HashSet::default();
    for obligation in &fragment.call_obligations {
        assert!(
            calls.insert(obligation.call),
            "one applicability obligation per call is required"
        );
        assert!(
            callee_references.insert(obligation.callee_reference),
            "one call-applicability obligation per callee reference is required"
        );
    }
    let mut callable_definitions = HashSet::default();
    for signature in &fragment.callable_signatures {
        assert!(
            callable_definitions.insert(signature.definition),
            "one signature property per callable definition is required"
        );
    }
}

fn frontier_sort_key(row: &LoweredTypedFrontier) -> SemanticId {
    row.slot
}

fn transfer_sort_key(row: &LoweredTypeTransfer) -> (SemanticId, u8, SemanticId, i64, SemanticId) {
    (
        row.source_slot,
        transfer_kind_rank(row.kind),
        row.rule.target_slot(),
        row.rule.indirection_delta(),
        row.rule.semantic(),
    )
}

fn intrinsic_sort_key(row: &LoweredIntrinsicSeed) -> (SemanticId, u8) {
    (row.frontier.slot(), intrinsic_kind_rank(row.kind))
}

fn projection_sort_key(row: &LoweredBindingProjection) -> (SemanticId, u8, SemanticId) {
    (
        row.reference,
        projection_kind_rank(row.kind),
        row.output_slot,
    )
}

fn declaration_type_sort_key(row: &LoweredDeclarationTypeProperty) -> (SemanticId, u8, SemanticId) {
    (
        row.definition,
        declaration_type_role_rank(row.role),
        row.slot,
    )
}

fn qualified_route_sort_key(
    row: &LoweredQualifiedSeededRoute,
) -> (SemanticId, u32, u8, SemanticId, SemanticId, SemanticId) {
    (
        row.reference,
        row.precedence_ordinal,
        namespace_rank(row.namespace),
        row.lookup,
        row.qualifier_slot,
        row.projection_output_slot,
    )
}

fn member_owner_sort_key(
    row: &LoweredMemberOwnerProperty,
) -> (SemanticId, u8, u8, u8, SemanticId, BindingNodeId) {
    (
        row.definition,
        member_kind_rank(row.kind),
        member_access_rank(row.access),
        member_qualifier_compatibility_rank(row.qualifier_compatibility),
        row.owner_definition,
        row.owner_scope_head,
    )
}

fn construction_requirement_sort_key(
    row: &LoweredConstructionRequirementProperty,
) -> (SemanticId, u8, SemanticId) {
    (
        row.definition,
        construction_requirement_rank(row.kind),
        row.required_owner_definition,
    )
}

fn supertype_sort_key(row: &LoweredSupertypeProperty) -> (SemanticId, u8, SemanticId, SemanticId) {
    (
        row.definition,
        supertype_kind_rank(row.kind),
        row.reference,
        row.frontier,
    )
}

fn property_gap_sort_key(
    row: &LoweredDefinitionPropertyGap,
) -> (SemanticId, u8, ResolutionSiteId, SemanticId, SemanticId) {
    (
        row.definition,
        gap_kind_rank(row.kind),
        row.source_site,
        row.frontier,
        row.reason_semantic,
    )
}

fn call_obligation_sort_key(row: &LoweredCallApplicabilityObligation) -> (SemanticId, SemanticId) {
    (row.callee_reference, row.call)
}

fn callable_signature_sort_key(row: &LoweredCallableSignatureProperty) -> SemanticId {
    row.definition
}

pub(super) fn call_semantic_identity(call: ResolutionSiteId) -> ResolutionSemanticIdentity {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-call-semantic-local:v2");
    hasher.field("call", &call.get().to_be_bytes());
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
}

fn transfer_rule_semantic_identity(fact: ResolutionTypeTransferFact) -> ResolutionSemanticIdentity {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-type-transfer-rule-local:v2");
    hasher.field("input", &fact.input.get().to_be_bytes());
    hasher.field("output", &fact.output.get().to_be_bytes());
    hasher.field("kind", &[transfer_kind_rank(fact.kind)]);
    match fact.value_transform {
        ResolutionTypeTransferValueTransform::Preserve => {
            hasher.field("value_transform", b"preserve");
        }
        ResolutionTypeTransferValueTransform::ToRuntime { addressable } => {
            hasher.field("value_transform", b"to-runtime");
            hasher.field("addressable", &[u8::from(addressable)]);
        }
        ResolutionTypeTransferValueTransform::ToNoValue => {
            hasher.field("value_transform", b"to-no-value");
        }
    }
    hasher.field(
        "indirection_delta",
        &i64::from(fact.indirection_delta).to_be_bytes(),
    );
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
}

fn intrinsic_type_semantic_identity(
    language: Language,
    kind: IntrinsicTypeKind,
    spelling: &str,
) -> ResolutionSemanticIdentity {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-intrinsic-type:v1");
    hasher.field("language", language.config_label().as_bytes());
    hasher.field("kind", &[intrinsic_kind_rank(kind)]);
    hasher.field("spelling", spelling.as_bytes());
    ResolutionSemanticIdentity::shared(hasher.finish())
}

fn unsupported_intrinsic_role_semantic_identity(
    slot: ResolutionTypeSlotId,
    role: ResolutionTypeSlotRole,
) -> ResolutionSemanticIdentity {
    let mut hasher =
        CanonicalHasher::new(b"bifrost-resolution-unsupported-intrinsic-role-local:v2");
    hasher.field("slot", &slot.get().to_be_bytes());
    hasher.field("role", &[type_slot_role_rank(role)]);
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
}

pub(super) const fn projection_kind_rank(kind: BindingProjectionKind) -> u8 {
    match kind {
        BindingProjectionKind::TargetTypeIdentity => 0,
        BindingProjectionKind::TargetDeclaredValueType => 1,
        BindingProjectionKind::TargetCallableResultType => 2,
        BindingProjectionKind::TargetConstructorOwnerType => 3,
        BindingProjectionKind::TargetTypeOrDeclaredValueType => 4,
    }
}

const fn namespace_rank(namespace: ResolutionNamespace) -> u8 {
    match namespace {
        ResolutionNamespace::Type => 0,
        ResolutionNamespace::Value => 1,
        ResolutionNamespace::Callable => 2,
        ResolutionNamespace::Constructor => 3,
        ResolutionNamespace::Macro => 4,
        ResolutionNamespace::Constant => 5,
        ResolutionNamespace::TypeOrValue => 6,
    }
}

const fn transfer_kind_rank(kind: ResolutionTypeTransferKind) -> u8 {
    match kind {
        ResolutionTypeTransferKind::DeclaredType => 0,
        ResolutionTypeTransferKind::Assignment => 1,
        ResolutionTypeTransferKind::Construction => 2,
        ResolutionTypeTransferKind::Receiver => 3,
        ResolutionTypeTransferKind::Argument => 4,
        ResolutionTypeTransferKind::Return => 5,
    }
}

const fn intrinsic_kind_rank(kind: IntrinsicTypeKind) -> u8 {
    match kind {
        IntrinsicTypeKind::Primitive => 0,
        IntrinsicTypeKind::LanguageBuiltin => 1,
    }
}

pub(super) const fn declaration_type_role_rank(role: DeclarationTypeRole) -> u8 {
    match role {
        DeclarationTypeRole::Value => 0,
        DeclarationTypeRole::Parameter => 1,
        DeclarationTypeRole::Return => 2,
    }
}

pub(super) const fn member_kind_rank(kind: ResolutionMemberKind) -> u8 {
    match kind {
        ResolutionMemberKind::NestedType => 0,
        ResolutionMemberKind::Method => 1,
        ResolutionMemberKind::Constructor => 2,
        ResolutionMemberKind::Field => 3,
        ResolutionMemberKind::AssociatedType => 4,
    }
}

const fn member_access_rank(access: ResolutionMemberAccess) -> u8 {
    match access {
        ResolutionMemberAccess::Instance => 0,
        ResolutionMemberAccess::Type => 1,
    }
}

pub(super) const fn member_qualifier_compatibility_rank(
    compatibility: ResolutionMemberQualifierCompatibility,
) -> u8 {
    match compatibility {
        ResolutionMemberQualifierCompatibility::RuntimeOnly => 0,
        ResolutionMemberQualifierCompatibility::TypeOnly => 1,
        ResolutionMemberQualifierCompatibility::RuntimeOrType => 2,
    }
}

const fn construction_requirement_rank(kind: ResolutionConstructionRequirementKind) -> u8 {
    match kind {
        ResolutionConstructionRequirementKind::EnclosingInstance => 0,
    }
}

const fn supertype_kind_rank(kind: ResolutionSupertypeKind) -> u8 {
    match kind {
        ResolutionSupertypeKind::Superclass => 0,
        ResolutionSupertypeKind::Interface => 1,
    }
}

const fn type_slot_role_rank(role: ResolutionTypeSlotRole) -> u8 {
    match role {
        ResolutionTypeSlotRole::TargetTypeIdentity => 0,
        ResolutionTypeSlotRole::DeclaredValue => 1,
        ResolutionTypeSlotRole::AssignmentValue => 2,
        ResolutionTypeSlotRole::ReturnValue => 3,
        ResolutionTypeSlotRole::Receiver => 4,
        ResolutionTypeSlotRole::Argument => 5,
        ResolutionTypeSlotRole::CallResult => 6,
        ResolutionTypeSlotRole::ExpressionValue => 7,
    }
}

const fn gap_kind_rank(kind: ResolutionGapKind) -> u8 {
    match kind {
        ResolutionGapKind::UnsupportedTypeSyntax => 0,
        ResolutionGapKind::UnsupportedExpression => 1,
        ResolutionGapKind::UnsupportedRoute => 2,
        ResolutionGapKind::UnsupportedScopeOrBinder => 3,
        ResolutionGapKind::AmbiguousQualifiedType => 4,
        ResolutionGapKind::InferredType => 5,
        ResolutionGapKind::PostfixArrayDimensions => 6,
        ResolutionGapKind::AmbiguousNumericLiteral => 7,
        ResolutionGapKind::ImplicitConstructor => 8,
        ResolutionGapKind::UnsupportedHierarchyTraversal => 9,
        ResolutionGapKind::UnsupportedVisibility => 10,
        ResolutionGapKind::UnsupportedImplicitReceiver => 11,
        ResolutionGapKind::UnsupportedCallApplicability => 12,
        ResolutionGapKind::UnsupportedPlacementBoundary => 13,
        ResolutionGapKind::MalformedSyntax => 14,
        ResolutionGapKind::UnsupportedMemberScope => 15,
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionFact, DeclarationTypeSlotFact, IntrinsicTypeSeedFact,
        PositionedIdentifierFact, ResolutionCallFact, ResolutionCallableSignatureFact,
        ResolutionConstructionRequirementFact, ResolutionDeclarationVisibilityFact,
        ResolutionGapFact, ResolutionIdentifierRole, ResolutionMemberOwnerFact, ResolutionNameFact,
        ResolutionNameId, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeKind,
        ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionSupertypeFact,
        ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeTransferFact,
        ResolutionVisibilityEligibilityFact,
    };

    use super::super::fact_lowering::lookup_semantic;
    use super::*;

    fn call_semantic(fragment: BindingFragmentId, call: ResolutionSiteId) -> SemanticId {
        call_semantic_identity(call).mount(fragment)
    }

    fn type_slot_semantic(fragment: BindingFragmentId, slot: ResolutionTypeSlotId) -> SemanticId {
        type_slot_semantic_identity(slot).mount(fragment)
    }

    fn scope_head_node(fragment: BindingFragmentId, scope: ResolutionScopeId) -> BindingNodeId {
        scope_head_node_identity(scope).mount(fragment)
    }

    fn reference_semantic(fragment: BindingFragmentId, site: ResolutionSiteId) -> SemanticId {
        reference_semantic_identity(site).mount(fragment)
    }

    fn fragment() -> BindingFragmentId {
        BindingFragmentId::hash_bytes(b"typed-fact-lowering-test-fragment")
    }

    fn name(id: u32, spelling: &str) -> ResolutionNameFact {
        ResolutionNameFact {
            id: ResolutionNameId::new(id),
            spelling: spelling.into(),
        }
    }

    fn scope(
        id: u32,
        parent: Option<u32>,
        owner: Option<u32>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeFact {
        ResolutionScopeFact {
            id: ResolutionScopeId::new(id),
            parent: parent.map(ResolutionScopeId::new),
            owner: owner.map(ResolutionSiteId::new),
            kind,
            start_byte,
            end_byte,
        }
    }

    fn site(id: u32, scope: u32, kind: ResolutionSiteKind, position: usize) -> ResolutionSiteFact {
        ResolutionSiteFact {
            id: ResolutionSiteId::new(id),
            scope: ResolutionScopeId::new(scope),
            kind,
            start_byte: position,
            end_byte: position + 1,
        }
    }

    fn identifier(
        site: u32,
        name: u32,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<u32>,
    ) -> PositionedIdentifierFact {
        PositionedIdentifierFact {
            site: ResolutionSiteId::new(site),
            name: ResolutionNameId::new(name),
            role,
            namespace,
            qualifier: qualifier.map(ResolutionTypeSlotId::new),
        }
    }

    fn slot(id: u32, site: u32, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotFact {
        ResolutionTypeSlotFact {
            id: ResolutionTypeSlotId::new(id),
            site: ResolutionSiteId::new(site),
            role,
        }
    }

    fn transfer(
        input: u32,
        output: u32,
        kind: ResolutionTypeTransferKind,
        delta: i8,
        value_transform: ResolutionTypeTransferValueTransform,
    ) -> ResolutionTypeTransferFact {
        ResolutionTypeTransferFact {
            input: ResolutionTypeSlotId::new(input),
            output: ResolutionTypeSlotId::new(output),
            kind,
            indirection_delta: delta,
            value_transform,
        }
    }

    fn visibility_eligibilities(
        declarations: impl IntoIterator<Item = u32>,
    ) -> Vec<ResolutionVisibilityEligibilityFact> {
        declarations
            .into_iter()
            .map(|declaration| ResolutionVisibilityEligibilityFact {
                declaration: ResolutionSiteId::new(declaration),
            })
            .collect()
    }

    fn declared_and_observed_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![name(0, "Base"), name(1, "Sub"), name(2, "x"), name(3, "f")],
            scopes: vec![scope(
                0,
                None,
                None,
                ResolutionScopeKind::CompilationUnit,
                0,
                200,
            )],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeReference, 1),
                site(1, 0, ResolutionSiteKind::ValueDeclaration, 10),
                // This runtime seed stands for the value produced by `new Sub`;
                // constructor projection is covered independently below.
                site(2, 0, ResolutionSiteKind::Literal, 20),
                site(3, 0, ResolutionSiteKind::CallableDeclaration, 30),
                site(4, 0, ResolutionSiteKind::TypeReference, 31),
            ],
            identifiers: vec![
                identifier(
                    1,
                    2,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                    None,
                ),
            ],
            type_slots: vec![
                slot(0, 0, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 1, ResolutionTypeSlotRole::DeclaredValue),
                slot(2, 2, ResolutionTypeSlotRole::ExpressionValue),
                slot(3, 1, ResolutionTypeSlotRole::AssignmentValue),
                slot(4, 4, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(5, 3, ResolutionTypeSlotRole::DeclaredValue),
                slot(6, 3, ResolutionTypeSlotRole::ReturnValue),
            ],
            declaration_type_slots: vec![
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(1),
                    slot: ResolutionTypeSlotId::new(1),
                    role: DeclarationTypeRole::Value,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(3),
                    slot: ResolutionTypeSlotId::new(5),
                    role: DeclarationTypeRole::Return,
                },
            ],
            type_transfers: vec![
                transfer(
                    0,
                    1,
                    ResolutionTypeTransferKind::DeclaredType,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    2,
                    3,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    4,
                    5,
                    ResolutionTypeTransferKind::DeclaredType,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    2,
                    6,
                    ResolutionTypeTransferKind::Return,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
            ],
            intrinsic_type_seeds: vec![
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(0),
                    name: ResolutionNameId::new(0),
                    kind: IntrinsicTypeKind::LanguageBuiltin,
                    indirection: 0,
                },
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(2),
                    name: ResolutionNameId::new(1),
                    kind: IntrinsicTypeKind::LanguageBuiltin,
                    indirection: 0,
                },
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(4),
                    name: ResolutionNameId::new(0),
                    kind: IntrinsicTypeKind::LanguageBuiltin,
                    indirection: 0,
                },
            ],
            callable_signatures: vec![ResolutionCallableSignatureFact {
                callable: ResolutionSiteId::new(3),
                type_parameter_count: 0,
            }],
            ..FileResolutionFacts::default()
        }
    }

    fn constructor_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![name(0, "Sub")],
            scopes: vec![
                scope(0, None, None, ResolutionScopeKind::CompilationUnit, 0, 100),
                scope(1, Some(0), Some(0), ResolutionScopeKind::TypeBody, 10, 90),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 1, ResolutionSiteKind::ConstructorDeclaration, 20),
                site(2, 0, ResolutionSiteKind::TypeReference, 92),
                site(3, 0, ResolutionSiteKind::ConstructorReference, 93),
                site(4, 0, ResolutionSiteKind::Call, 91),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Constructor,
                    None,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    3,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Constructor,
                    Some(0),
                ),
            ],
            type_slots: vec![
                slot(0, 2, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 4, ResolutionTypeSlotRole::CallResult),
            ],
            binding_projections: vec![
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(2),
                    output: ResolutionTypeSlotId::new(0),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(3),
                    output: ResolutionTypeSlotId::new(1),
                    kind: BindingProjectionKind::TargetConstructorOwnerType,
                },
            ],
            calls: vec![ResolutionCallFact {
                call: ResolutionSiteId::new(4),
                callee: ResolutionSiteId::new(3),
                receiver: None,
                result: ResolutionTypeSlotId::new(1),
                explicit_type_argument_count: 0,
            }],
            callable_signatures: vec![ResolutionCallableSignatureFact {
                callable: ResolutionSiteId::new(1),
                type_parameter_count: 0,
            }],
            member_owners: vec![ResolutionMemberOwnerFact {
                member: ResolutionSiteId::new(1),
                owner: ResolutionSiteId::new(0),
                kind: ResolutionMemberKind::Constructor,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            }],
            declaration_visibilities: vec![
                ResolutionDeclarationVisibilityFact {
                    declaration: ResolutionSiteId::new(0),
                    visibility: DeclaredVisibility::Public,
                },
                ResolutionDeclarationVisibilityFact {
                    declaration: ResolutionSiteId::new(1),
                    visibility: DeclaredVisibility::Public,
                },
            ],
            visibility_eligibilities: visibility_eligibilities([0, 1]),
            ..FileResolutionFacts::default()
        }
    }

    fn hierarchy_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![name(0, "Sub"), name(1, "Base")],
            scopes: vec![
                scope(0, None, None, ResolutionScopeKind::CompilationUnit, 0, 100),
                scope(1, Some(0), Some(0), ResolutionScopeKind::TypeBody, 10, 90),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeReference, 5),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
            ],
            type_slots: vec![slot(0, 1, ResolutionTypeSlotRole::TargetTypeIdentity)],
            binding_projections: vec![BindingProjectionFact {
                reference: ResolutionSiteId::new(1),
                output: ResolutionTypeSlotId::new(0),
                kind: BindingProjectionKind::TargetTypeIdentity,
            }],
            supertypes: vec![ResolutionSupertypeFact {
                subtype: ResolutionSiteId::new(0),
                supertype_reference: ResolutionSiteId::new(1),
                supertype_slot: ResolutionTypeSlotId::new(0),
                kind: ResolutionSupertypeKind::Superclass,
            }],
            gaps: vec![
                ResolutionGapFact {
                    site: ResolutionSiteId::new(0),
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: ResolutionSiteId::new(1),
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
            ],
            declaration_visibilities: vec![ResolutionDeclarationVisibilityFact {
                declaration: ResolutionSiteId::new(0),
                visibility: DeclaredVisibility::Public,
            }],
            visibility_eligibilities: visibility_eligibilities([0]),
            ..FileResolutionFacts::default()
        }
    }

    #[test]
    #[should_panic(expected = "visibility row must name a supported type")]
    fn source_visibility_requires_producer_eligibility() {
        let mut facts = hierarchy_facts();
        facts.visibility_eligibilities.clear();
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    #[should_panic(expected = "one visibility eligibility row per declaration")]
    fn source_visibility_eligibility_is_unique() {
        let mut facts = hierarchy_facts();
        facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact {
                declaration: ResolutionSiteId::new(0),
            });
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    fn call_applicability_facts() -> FileResolutionFacts {
        let mut facts = constructor_facts();
        facts.calls[0].explicit_type_argument_count = 2;
        facts.callable_signatures[0].type_parameter_count = 3;
        facts.names.extend([name(1, "first"), name(2, "rest")]);
        facts.sites.extend([
            site(5, 1, ResolutionSiteKind::ValueDeclaration, 30),
            site(6, 1, ResolutionSiteKind::ValueDeclaration, 31),
        ]);
        facts.identifiers.extend([
            identifier(
                5,
                1,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ),
            identifier(
                6,
                2,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ),
        ]);
        facts.type_slots.extend([
            slot(2, 5, ResolutionTypeSlotRole::DeclaredValue),
            slot(3, 6, ResolutionTypeSlotRole::DeclaredValue),
            slot(4, 4, ResolutionTypeSlotRole::Argument),
            slot(5, 4, ResolutionTypeSlotRole::Argument),
        ]);
        facts.declaration_type_slots.extend([
            DeclarationTypeSlotFact {
                declaration: ResolutionSiteId::new(5),
                slot: ResolutionTypeSlotId::new(2),
                role: DeclarationTypeRole::Parameter,
            },
            DeclarationTypeSlotFact {
                declaration: ResolutionSiteId::new(6),
                slot: ResolutionTypeSlotId::new(3),
                role: DeclarationTypeRole::Parameter,
            },
        ]);
        // Intentionally reverse both row families. Lowering owns the ordered
        // normalized representation, not producer insertion order.
        facts.call_arguments = vec![
            ResolutionCallArgumentFact {
                call: ResolutionSiteId::new(4),
                ordinal: 1,
                value: ResolutionTypeSlotId::new(5),
            },
            ResolutionCallArgumentFact {
                call: ResolutionSiteId::new(4),
                ordinal: 0,
                value: ResolutionTypeSlotId::new(4),
            },
        ];
        facts.callable_parameters = vec![
            ResolutionCallableParameterFact {
                callable: ResolutionSiteId::new(1),
                ordinal: 1,
                parameter: ResolutionSiteId::new(6),
                value_type: ResolutionTypeSlotId::new(3),
                repeated: true,
            },
            ResolutionCallableParameterFact {
                callable: ResolutionSiteId::new(1),
                ordinal: 0,
                parameter: ResolutionSiteId::new(5),
                value_type: ResolutionTypeSlotId::new(2),
                repeated: false,
            },
        ];
        facts
    }

    fn nested_constructor_facts() -> FileResolutionFacts {
        let mut facts = constructor_facts();
        facts.names.push(name(1, "Outer"));
        facts
            .sites
            .push(site(5, 0, ResolutionSiteKind::TypeDeclaration, 0));
        facts.identifiers.push(identifier(
            5,
            1,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        ));
        facts.scopes.push(scope(
            2,
            Some(0),
            Some(5),
            ResolutionScopeKind::TypeBody,
            0,
            100,
        ));
        facts.sites[0].scope = ResolutionScopeId::new(2);
        facts.scopes[1].parent = Some(ResolutionScopeId::new(2));
        facts.construction_requirements = vec![ResolutionConstructionRequirementFact {
            constructed_type: ResolutionSiteId::new(0),
            required_owner: ResolutionSiteId::new(5),
            kind: ResolutionConstructionRequirementKind::EnclosingInstance,
        }];
        facts.member_owners.push(ResolutionMemberOwnerFact {
            member: ResolutionSiteId::new(0),
            owner: ResolutionSiteId::new(5),
            kind: ResolutionMemberKind::NestedType,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        });
        facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration: ResolutionSiteId::new(5),
                visibility: DeclaredVisibility::Public,
            });
        facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact {
                declaration: ResolutionSiteId::new(5),
            });
        facts
    }

    fn reversed<T>(items: impl IntoIterator<Item = T>) -> Vec<T> {
        let mut items = items.into_iter().collect::<Vec<_>>();
        items.reverse();
        items
    }

    fn hydrated_clone(lowered: &LoweredTypedFragment) -> LoweredTypedFragment {
        LoweredTypedFragment::new(
            lowered.fragment(),
            lowered.language(),
            reversed(
                lowered
                    .frontiers()
                    .iter()
                    .map(|row| LoweredTypedFrontier::new(row.slot(), row.role())),
            ),
            reversed(lowered.transfers().iter().map(|row| {
                LoweredTypeTransfer::new(row.source_slot(), row.kind(), row.rule().clone())
            })),
            reversed(
                lowered
                    .intrinsic_seeds()
                    .iter()
                    .map(|row| LoweredIntrinsicSeed::new(row.kind(), row.frontier().clone())),
            ),
            reversed(lowered.projections().iter().map(|row| {
                LoweredBindingProjection::new(row.reference(), row.output_slot(), row.kind())
            })),
            reversed(lowered.qualified_routes().iter().map(|row| {
                LoweredQualifiedSeededRoute::new(
                    row.reference(),
                    row.qualifier_slot(),
                    row.lookup(),
                    row.namespace(),
                    row.precedence_ordinal(),
                    row.projection_output_slot(),
                    row.projection_kind(),
                    row.coarse_gap_reason(),
                )
            })),
            reversed(lowered.declaration_types().iter().map(|row| {
                LoweredDeclarationTypeProperty::new(row.definition(), row.slot(), row.role())
            })),
            reversed(lowered.declaration_visibilities().iter().map(|row| {
                LoweredDeclarationVisibilityProperty::new(row.definition(), row.visibility())
            })),
            reversed(
                lowered
                    .member_scopes()
                    .iter()
                    .map(|row| LoweredMemberScopeProperty::new(row.definition(), row.scope_head())),
            ),
            reversed(lowered.member_owners().iter().map(|row| {
                LoweredMemberOwnerProperty::new(
                    row.definition(),
                    row.owner_definition(),
                    row.owner_scope_head(),
                    row.kind(),
                    row.access(),
                    row.qualifier_compatibility(),
                )
            })),
            reversed(lowered.construction_requirements().iter().map(|row| {
                LoweredConstructionRequirementProperty::new(
                    row.definition(),
                    row.required_owner_definition(),
                    row.kind(),
                )
            })),
            reversed(lowered.supertypes().iter().map(|row| {
                LoweredSupertypeProperty::new(
                    row.definition(),
                    row.reference(),
                    row.frontier(),
                    row.kind(),
                )
            })),
            reversed(lowered.property_gaps().iter().map(|row| {
                LoweredDefinitionPropertyGap::new(
                    row.definition(),
                    row.source_site(),
                    row.kind(),
                    row.frontier(),
                    row.reason_semantic(),
                )
            })),
            reversed(lowered.call_obligations().iter().map(|row| {
                LoweredCallApplicabilityObligation::new(
                    row.call(),
                    row.callee_reference(),
                    row.receiver_slot(),
                    row.result_slot(),
                    row.argument_slots().to_vec(),
                    row.eligible_rules().to_vec(),
                    row.explicit_type_argument_count(),
                    row.applicability_reason(),
                    row.completion().clone(),
                )
            })),
            reversed(lowered.callable_signatures().iter().map(|row| {
                let parameters = reversed(row.parameters().iter().map(|parameter| {
                    LoweredCallableParameterProperty::new(
                        parameter.ordinal(),
                        parameter.definition(),
                        parameter.slot(),
                        parameter.repeated(),
                    )
                }));
                LoweredCallableSignatureProperty::new(
                    row.definition(),
                    row.type_parameter_count(),
                    parameters,
                    row.completion().clone(),
                )
            })),
        )
    }

    fn renormalize_hydrated(lowered: LoweredTypedFragment) -> LoweredTypedFragment {
        let LoweredTypedFragment {
            fragment,
            language,
            frontiers,
            transfers,
            intrinsic_seeds,
            projections,
            qualified_routes,
            declaration_types,
            declaration_visibilities,
            member_scopes,
            member_owners,
            construction_requirements,
            supertypes,
            property_gaps,
            call_obligations,
            callable_signatures,
        } = lowered;
        LoweredTypedFragment::new(
            fragment,
            language,
            frontiers,
            transfers,
            intrinsic_seeds,
            projections,
            qualified_routes,
            declaration_types,
            declaration_visibilities,
            member_scopes,
            member_owners,
            construction_requirements,
            supertypes,
            property_gaps,
            call_obligations,
            callable_signatures,
        )
    }

    fn assert_all_row_slots_are_in_the_inventory(
        facts: &FileResolutionFacts,
        lowered: &LoweredTypedFragment,
    ) {
        let inventory = lowered
            .frontiers()
            .iter()
            .map(LoweredTypedFrontier::slot)
            .collect::<HashSet<_>>();
        let assert_present = |slot| assert!(inventory.contains(&slot), "missing slot {slot:?}");

        for transfer in lowered.transfers() {
            assert_present(transfer.source_slot());
            assert_present(transfer.rule().target_slot());
        }
        for seed in lowered.intrinsic_seeds() {
            assert_present(seed.frontier().slot());
        }
        for projection in lowered.projections() {
            assert_present(projection.output_slot());
        }
        for route in lowered.qualified_routes() {
            assert_present(route.qualifier_slot());
            assert_present(route.projection_output_slot());
        }
        for property in lowered.declaration_types() {
            assert_present(property.slot());
        }
        for property in lowered.supertypes() {
            assert_present(property.frontier());
        }
        for obligation in lowered.call_obligations() {
            if let Some(receiver) = obligation.receiver_slot() {
                assert_present(receiver);
            }
            assert_present(obligation.result_slot());
            for &argument in obligation.argument_slots() {
                assert_present(argument);
            }
        }
        for signature in lowered.callable_signatures() {
            for parameter in signature.parameters() {
                assert_present(parameter.slot());
            }
        }
        for gap in lowered.property_gaps() {
            if !inventory.contains(&gap.frontier()) {
                assert_eq!(
                    gap.frontier(),
                    site_type_frontier_semantic(lowered.fragment(), gap.source_site())
                );
                assert!(
                    facts
                        .type_slots
                        .iter()
                        .all(|slot| slot.site != gap.source_site()),
                    "only a gap on a site without a real type slot may use a synthetic frontier"
                );
            }
        }
    }

    fn minimal_hydrated_fragment(
        frontiers: Vec<LoweredTypedFrontier>,
        transfers: Vec<LoweredTypeTransfer>,
        intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
        projections: Vec<LoweredBindingProjection>,
    ) -> LoweredTypedFragment {
        LoweredTypedFragment::new(
            fragment(),
            Language::Rust,
            frontiers,
            transfers,
            intrinsic_seeds,
            projections,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn hydrated_intrinsic_fragment(
        role: ResolutionTypeSlotRole,
        values: Vec<ResolutionSlotValue>,
        completion: ResolutionCompletion,
    ) -> LoweredTypedFragment {
        let slot = SemanticId::hash_bytes(b"hydrated-intrinsic-slot");
        minimal_hydrated_fragment(
            vec![LoweredTypedFrontier::new(slot, role)],
            Vec::new(),
            vec![LoweredIntrinsicSeed::new(
                IntrinsicTypeKind::LanguageBuiltin,
                TypedFrontierState::new(slot, values, completion),
            )],
            Vec::new(),
        )
    }

    fn set_frontier_role(
        lowered: &mut LoweredTypedFragment,
        slot: SemanticId,
        role: ResolutionTypeSlotRole,
    ) {
        lowered
            .frontiers
            .iter_mut()
            .find(|frontier| frontier.slot == slot)
            .unwrap_or_else(|| panic!("missing test frontier {slot:?}"))
            .role = role;
    }

    fn set_first_intrinsic_completion(
        lowered: &mut LoweredTypedFragment,
        completion: ResolutionCompletion,
    ) {
        let seed = &mut lowered.intrinsic_seeds[0];
        seed.frontier = TypedFrontierState::new(
            seed.frontier.slot(),
            seed.frontier.possible_values().to_vec(),
            completion,
        );
    }

    #[test]
    fn unproduced_type_slots_remain_explicit_with_their_exact_roles() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(
                0,
                None,
                None,
                ResolutionScopeKind::CompilationUnit,
                0,
                20,
            )],
            sites: vec![site(0, 0, ResolutionSiteKind::Literal, 1)],
            type_slots: vec![
                slot(1, 0, ResolutionTypeSlotRole::Receiver),
                slot(0, 0, ResolutionTypeSlotRole::ExpressionValue),
            ],
            ..FileResolutionFacts::default()
        };

        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let roles = lowered
            .frontiers()
            .iter()
            .map(|frontier| (frontier.slot(), frontier.role()))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            roles,
            HashMap::from_iter([
                (
                    type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0)),
                    ResolutionTypeSlotRole::ExpressionValue,
                ),
                (
                    type_slot_semantic(fragment(), ResolutionTypeSlotId::new(1)),
                    ResolutionTypeSlotRole::Receiver,
                ),
            ])
        );
        assert!(lowered.transfers().is_empty());
        assert!(lowered.intrinsic_seeds().is_empty());
        assert!(lowered.projections().is_empty());
    }

    #[test]
    fn every_real_slot_reference_is_declared_in_the_frontier_inventory() {
        let mut calls = call_applicability_facts();
        calls
            .type_slots
            .push(slot(6, 4, ResolutionTypeSlotRole::Receiver));
        calls.calls[0].receiver = Some(ResolutionTypeSlotId::new(6));

        for facts in [declared_and_observed_facts(), calls, hierarchy_facts()] {
            let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
            assert_all_row_slots_are_in_the_inventory(&facts, &lowered);
        }
    }

    #[test]
    fn hydration_constructors_round_trip_and_canonicalize_every_row_family() {
        for facts in [
            declared_and_observed_facts(),
            call_applicability_facts(),
            hierarchy_facts(),
            nested_constructor_facts(),
        ] {
            let expected = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
            assert_eq!(hydrated_clone(&expected), expected);
        }
    }

    #[test]
    fn non_java_source_visibility_inventory_uses_the_common_property_family() {
        let facts = constructor_facts();
        let lowered = lower_typed_resolution_facts(fragment(), Language::Go, &facts);
        assert_eq!(
            lowered.declaration_visibilities().len(),
            facts.declaration_visibilities.len()
        );
    }

    #[test]
    fn non_java_hydrated_visibility_inventory_uses_the_common_property_family() {
        let mut hydrated =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        hydrated.language = Language::Go;
        let expected_count = hydrated.declaration_visibilities().len();
        let normalized = renormalize_hydrated(hydrated);
        assert_eq!(normalized.language(), Language::Go);
        assert_eq!(normalized.declaration_visibilities().len(), expected_count);
    }

    #[test]
    #[should_panic(expected = "one typed frontier per stable slot is required")]
    fn hydration_rejects_duplicate_frontier_rows() {
        let frontier = LoweredTypedFrontier::new(
            SemanticId::hash_bytes(b"duplicate-frontier"),
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ =
            minimal_hydrated_fragment(vec![frontier, frontier], Vec::new(), Vec::new(), Vec::new());
    }

    #[test]
    #[should_panic(expected = "type-transfer target names undeclared typed frontier")]
    fn hydration_rejects_a_row_owned_slot_missing_from_the_inventory() {
        let source = SemanticId::hash_bytes(b"declared-source");
        let target = SemanticId::hash_bytes(b"missing-target");
        let transfer = LoweredTypeTransfer::new(
            source,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                SemanticId::hash_bytes(b"transfer"),
                target,
                0,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        );
        let _ = minimal_hydrated_fragment(
            vec![LoweredTypedFrontier::new(
                source,
                ResolutionTypeSlotRole::ExpressionValue,
            )],
            vec![transfer],
            Vec::new(),
            Vec::new(),
        );
    }

    #[test]
    #[should_panic(expected = "multiple output producers")]
    fn hydration_rejects_multiple_affirmative_producers_for_one_frontier() {
        let source = SemanticId::hash_bytes(b"producer-source");
        let output = SemanticId::hash_bytes(b"producer-output");
        let transfer = LoweredTypeTransfer::new(
            source,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                SemanticId::hash_bytes(b"producer-transfer"),
                output,
                0,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        );
        let projection = LoweredBindingProjection::new(
            SemanticId::hash_bytes(b"producer-reference"),
            output,
            BindingProjectionKind::TargetTypeIdentity,
        );
        let _ = minimal_hydrated_fragment(
            vec![
                LoweredTypedFrontier::new(source, ResolutionTypeSlotRole::ExpressionValue),
                LoweredTypedFrontier::new(output, ResolutionTypeSlotRole::AssignmentValue),
            ],
            vec![transfer],
            Vec::new(),
            vec![projection],
        );
    }

    #[test]
    #[should_panic(expected = "parameter ordinals must be contiguous from zero")]
    fn hydration_rejects_a_noncanonical_signature_parameter_set() {
        let _ = LoweredCallableSignatureProperty::new(
            SemanticId::hash_bytes(b"callable"),
            0,
            vec![LoweredCallableParameterProperty::new(
                1,
                SemanticId::hash_bytes(b"parameter"),
                SemanticId::hash_bytes(b"parameter-slot"),
                false,
            )],
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    fn callable_signature_polled_clone_matches_canonical_construction_and_cancels_atomically() {
        let parameters = (0_u32..300)
            .map(|ordinal| {
                let bytes = ordinal.to_le_bytes();
                LoweredCallableParameterProperty::new(
                    ordinal,
                    SemanticId::hash_bytes([b"parameter-definition".as_slice(), &bytes].concat()),
                    SemanticId::hash_bytes([b"parameter-slot".as_slice(), &bytes].concat()),
                    ordinal == 299,
                )
            })
            .collect::<Vec<_>>();
        let completion = ResolutionCompletion::incomplete((0_u32..300).map(|ordinal| {
            let bytes = ordinal.to_le_bytes();
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
                [b"signature-reason".as_slice(), &bytes].concat(),
            ))
        }));
        let signature = LoweredCallableSignatureProperty::new(
            SemanticId::hash_bytes(b"polled-signature"),
            3,
            parameters,
            completion,
        );

        let cloned = signature
            .clone_with_poll(&mut || false)
            .expect("live signature clone");
        assert_eq!(cloned, signature);
        let canonical = LoweredCallableSignatureProperty::from_canonical_parts_with_poll(
            signature.definition(),
            signature.type_parameter_count(),
            signature.parameters().to_vec().into_boxed_slice(),
            signature.completion().clone(),
            &mut || false,
        )
        .expect("live canonical signature construction");
        assert_eq!(canonical, signature);

        let mut parameter_polls = 0_usize;
        assert!(
            signature
                .clone_with_poll(&mut || {
                    parameter_polls += 1;
                    parameter_polls == 17
                })
                .is_none()
        );
        assert_eq!(parameter_polls, 17);

        let completion_only = LoweredCallableSignatureProperty::new(
            SemanticId::hash_bytes(b"completion-only-polled-signature"),
            0,
            Vec::new(),
            signature.completion().clone(),
        );
        let mut completion_polls = 0_usize;
        assert!(
            completion_only
                .clone_with_poll(&mut || {
                    completion_polls += 1;
                    completion_polls == 17
                })
                .is_none()
        );
        assert_eq!(completion_polls, 17);
    }

    #[test]
    #[should_panic(expected = "qualified route must name its exact binding projection")]
    fn hydration_rejects_a_qualified_route_without_its_projection() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        lowered.projections.clear();
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "member owner must name its declaring type's exact member scope")]
    fn hydration_rejects_a_member_owner_without_its_scope_property() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        let removed_type = lowered.member_scopes[0].definition();
        lowered.member_scopes.clear();
        lowered
            .declaration_visibilities
            .retain(|property| property.definition() != removed_type);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "call applicability completion must retain its declared applicability reason"
    )]
    fn hydration_rejects_a_call_without_its_applicability_reason() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        lowered.call_obligations[0].completion = ResolutionCompletion::Complete;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "intrinsic type seed completion cannot persist operation-local cancellation"
    )]
    fn hydration_rejects_operation_local_cancellation_evidence() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let seed = &mut lowered.intrinsic_seeds[0];
        seed.frontier = TypedFrontierState::new(
            seed.frontier.slot(),
            seed.frontier.possible_values().to_vec(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "incomplete completion requires at least one reason")]
    fn hydration_rejects_an_empty_incomplete_completion() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        set_first_intrinsic_completion(
            &mut lowered,
            ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into()),
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "incomplete reasons must be strictly sorted and unique")]
    fn hydration_rejects_noncanonical_incomplete_reason_order() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let mut reasons = vec![
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(b"first")),
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(b"second")),
        ];
        reasons.sort_unstable();
        reasons.reverse();
        set_first_intrinsic_completion(
            &mut lowered,
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into()),
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "incomplete reasons must be strictly sorted and unique")]
    fn hydration_rejects_duplicate_incomplete_reasons() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"duplicate-completion-reason",
        ));
        set_first_intrinsic_completion(
            &mut lowered,
            ResolutionCompletion::Incomplete(vec![reason, reason].into_boxed_slice().into()),
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "TargetTypeIdentity intrinsic seed must contain exactly one TypeObject value"
    )]
    fn hydration_rejects_a_complete_empty_supported_intrinsic_seed() {
        let _ = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::TargetTypeIdentity,
            Vec::new(),
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    #[should_panic(
        expected = "TargetTypeIdentity intrinsic seed must contain exactly one TypeObject value"
    )]
    fn hydration_rejects_an_intrinsic_value_category_that_disagrees_with_its_role() {
        let ty = ResolutionTypeRef::new(SemanticId::hash_bytes(b"runtime-not-type-object"), 0);
        let _ = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::TargetTypeIdentity,
            vec![ResolutionSlotValue::runtime(ty, false)],
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    #[should_panic(
        expected = "TargetTypeIdentity intrinsic seed must contain exactly one TypeObject value"
    )]
    fn hydration_rejects_multiple_intrinsic_values() {
        let _ = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::TargetTypeIdentity,
            vec![
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    SemanticId::hash_bytes(b"first-intrinsic-type"),
                    0,
                )),
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    SemanticId::hash_bytes(b"second-intrinsic-type"),
                    0,
                )),
            ],
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    #[should_panic(
        expected = "ExpressionValue intrinsic seed must contain exactly one non-addressable Runtime value"
    )]
    fn hydration_rejects_an_addressable_intrinsic_expression_value() {
        let ty = ResolutionTypeRef::new(SemanticId::hash_bytes(b"addressable-intrinsic"), 0);
        let _ = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::ExpressionValue,
            vec![ResolutionSlotValue::runtime(ty, true)],
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    #[should_panic(
        expected = "unsupported intrinsic seed role AssignmentValue must remain incomplete"
    )]
    fn hydration_rejects_a_complete_unsupported_intrinsic_role() {
        let _ = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::AssignmentValue,
            Vec::new(),
            ResolutionCompletion::Complete,
        );
    }

    #[test]
    fn hydration_accepts_an_empty_incomplete_unsupported_intrinsic_role() {
        let reason = SemanticId::hash_bytes(b"unsupported-intrinsic-role");
        let lowered = hydrated_intrinsic_fragment(
            ResolutionTypeSlotRole::AssignmentValue,
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )]),
        );
        assert!(
            lowered.intrinsic_seeds()[0]
                .frontier()
                .possible_values()
                .is_empty()
        );
        assert!(matches!(
            lowered.intrinsic_seeds()[0].frontier().completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    #[should_panic(expected = "type-transfer kind and output role disagree")]
    fn hydration_rejects_a_transfer_output_with_the_wrong_role() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let target = lowered
            .transfers
            .iter()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::Assignment)
            .expect("assignment transfer")
            .rule
            .target_slot();
        set_frontier_role(&mut lowered, target, ResolutionTypeSlotRole::ReturnValue);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "declared-type transfer input must retain a type object")]
    fn hydration_rejects_a_declared_type_transfer_from_a_runtime_role() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let source = lowered
            .transfers
            .iter()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::DeclaredType)
            .expect("declared-type transfer")
            .source_slot;
        set_frontier_role(
            &mut lowered,
            source,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "binding projection kind and output role disagree")]
    fn hydration_rejects_a_projection_output_with_the_wrong_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        let output = lowered.projections[0].output_slot;
        set_frontier_role(
            &mut lowered,
            output,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "declaration type property must name a DeclaredValue frontier")]
    fn hydration_rejects_a_declaration_property_with_the_wrong_slot_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let slot = lowered.declaration_types[0].slot;
        set_frontier_role(&mut lowered, slot, ResolutionTypeSlotRole::AssignmentValue);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "supertype property must name a TargetTypeIdentity frontier")]
    fn hydration_rejects_a_supertype_with_the_wrong_frontier_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        let frontier = SemanticId::hash_bytes(b"wrong-role-supertype-frontier");
        lowered.frontiers.push(LoweredTypedFrontier::new(
            frontier,
            ResolutionTypeSlotRole::ExpressionValue,
        ));
        lowered.supertypes[0].frontier = frontier;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "supertype property requires its exact TargetTypeIdentity projection"
    )]
    fn hydration_rejects_a_supertype_without_its_exact_projection() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        lowered.projections.clear();
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "call result must name a CallResult frontier")]
    fn hydration_rejects_a_call_result_with_the_wrong_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let obligation = &lowered.call_obligations[0];
        let callee = obligation.callee_reference;
        let result = obligation.result_slot;
        lowered
            .projections
            .retain(|projection| projection.reference != callee);
        lowered
            .qualified_routes
            .retain(|route| route.reference != callee);
        set_frontier_role(
            &mut lowered,
            result,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "call receiver must name a Receiver frontier")]
    fn hydration_rejects_a_call_receiver_with_the_wrong_role() {
        let mut facts = call_applicability_facts();
        facts
            .type_slots
            .push(slot(6, 4, ResolutionTypeSlotRole::Receiver));
        facts.calls[0].receiver = Some(ResolutionTypeSlotId::new(6));
        let mut lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let receiver = lowered.call_obligations[0]
            .receiver_slot
            .expect("receiver slot");
        set_frontier_role(
            &mut lowered,
            receiver,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "call argument must name an Argument frontier")]
    fn hydration_rejects_a_call_argument_with_the_wrong_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let argument = lowered.call_obligations[0].argument_slots[0];
        set_frontier_role(
            &mut lowered,
            argument,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "call applicability obligation requires its result binding projection"
    )]
    fn hydration_rejects_a_call_without_its_result_projection() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let callee = lowered.call_obligations[0].callee_reference;
        lowered
            .projections
            .retain(|projection| projection.reference != callee);
        lowered
            .qualified_routes
            .retain(|route| route.reference != callee);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "callable parameter must name a DeclaredValue frontier")]
    fn hydration_rejects_a_callable_parameter_with_the_wrong_slot_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let parameter = lowered.callable_signatures[0].parameters[0];
        lowered.declaration_types.retain(|property| {
            (property.definition, property.slot) != (parameter.definition, parameter.slot)
        });
        set_frontier_role(
            &mut lowered,
            parameter.slot,
            ResolutionTypeSlotRole::AssignmentValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "callable parameter requires its matching Parameter declaration type property"
    )]
    fn hydration_rejects_a_callable_parameter_without_its_declaration_property() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let parameter = lowered.callable_signatures[0].parameters[0];
        lowered.declaration_types.retain(|property| {
            (property.definition, property.slot) != (parameter.definition, parameter.slot)
        });
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "callable parameter definition may belong to only one signature")]
    fn hydration_rejects_one_parameter_definition_shared_by_two_signatures() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &call_applicability_facts());
        let parameter = lowered.callable_signatures[0].parameters[0];
        lowered
            .callable_signatures
            .push(LoweredCallableSignatureProperty::new(
                SemanticId::hash_bytes(b"second-callable"),
                0,
                vec![LoweredCallableParameterProperty::new(
                    0,
                    parameter.definition,
                    parameter.slot,
                    false,
                )],
                ResolutionCompletion::Complete,
            ));
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "construction requirement requires matching nested-type ownership")]
    fn hydration_rejects_a_construction_requirement_without_nested_type_ownership() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &nested_constructor_facts());
        lowered
            .member_owners
            .retain(|owner| owner.kind != ResolutionMemberKind::NestedType);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "must have the exact source-lowerable namespace and precedence shape"
    )]
    fn hydration_rejects_an_ordinary_projection_route_with_the_wrong_shape() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        lowered.qualified_routes[0].namespace = ResolutionNamespace::Value;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "must have the exact source-lowerable namespace and precedence shape"
    )]
    fn hydration_rejects_an_incomplete_type_or_value_route_pair() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        let reference = lowered.qualified_routes[0].reference;
        let projection = lowered
            .projections
            .iter_mut()
            .find(|projection| projection.reference == reference)
            .expect("qualified projection");
        projection.kind = BindingProjectionKind::TargetTypeOrDeclaredValueType;
        let output = projection.output_slot;
        let route = &mut lowered.qualified_routes[0];
        route.projection_kind = BindingProjectionKind::TargetTypeOrDeclaredValueType;
        route.namespace = ResolutionNamespace::Value;
        route.precedence_ordinal = 0;
        set_frontier_role(
            &mut lowered,
            output,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "constructor projection qualifier must retain a type object")]
    fn hydration_rejects_a_constructor_route_with_a_runtime_qualifier_role() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        let qualifier = lowered.qualified_routes[0].qualifier_slot;
        lowered
            .projections
            .retain(|projection| projection.output_slot != qualifier);
        set_frontier_role(
            &mut lowered,
            qualifier,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "type-transfer rule semantic must be unique within a fragment")]
    fn hydration_rejects_duplicate_transfer_rule_semantics() {
        let mut lowered = lower_typed_resolution_facts(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        );
        let semantic = lowered.transfers[0].rule.semantic();
        let replacement = {
            let duplicate = &lowered.transfers[1];
            LoweredTypeTransfer::new(
                duplicate.source_slot,
                duplicate.kind,
                TypeTransferRule::new(
                    semantic,
                    duplicate.rule.target_slot(),
                    duplicate.rule.indirection_delta(),
                    duplicate.rule.value_transform(),
                    duplicate.rule.completion().clone(),
                ),
            )
        };
        lowered.transfers[1] = replacement;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "qualified route (reference, precedence ordinal) must be unique")]
    fn hydration_rejects_duplicate_qualified_route_ordinals() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        let duplicate = lowered.qualified_routes[0];
        lowered.qualified_routes.push(duplicate);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "qualified-route coarse gap reason may belong to only one reference per fragment"
    )]
    fn hydration_rejects_one_coarse_gap_reason_reused_by_two_references() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &constructor_facts());
        let mut second_reference = lowered.qualified_routes[0];
        second_reference.reference = SemanticId::hash_bytes(b"second-qualified-reference");
        lowered.qualified_routes.push(second_reference);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "member-scope head may belong to only one type definition")]
    fn hydration_rejects_a_member_scope_head_shared_by_two_definitions() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &nested_constructor_facts());
        assert!(lowered.member_scopes.len() >= 2);
        let shared_head = lowered.member_scopes[0].scope_head;
        lowered.member_scopes[1].scope_head = shared_head;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "definition property-gap SQL identity must be unique")]
    fn hydration_rejects_duplicate_property_gap_sql_identities() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        let mut duplicate = lowered.property_gaps[0];
        duplicate.source_site = ResolutionSiteId::new(99);
        duplicate.kind = ResolutionGapKind::MalformedSyntax;
        lowered.property_gaps.push(duplicate);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "one definition owner per property-gap source provenance is required"
    )]
    fn hydration_rejects_conflicting_property_gap_owners() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        let mut conflicting = lowered.property_gaps[0];
        conflicting.definition = SemanticId::hash_bytes(b"conflicting-property-gap-owner");
        lowered.property_gaps.push(conflicting);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "definition property gap kind is not source-lowerable")]
    fn hydration_rejects_an_unsupported_definition_property_gap_kind() {
        let mut lowered =
            lower_typed_resolution_facts(fragment(), Language::Java, &hierarchy_facts());
        lowered.property_gaps[0].kind = ResolutionGapKind::UnsupportedExpression;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    fn declared_base_types_remain_separate_from_observed_sub_values() {
        let facts = declared_and_observed_facts();
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let base_type = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0))
            })
            .expect("Base annotation seed");
        let sub_value = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(2))
            })
            .expect("new Sub value seed");
        assert!(matches!(
            base_type.frontier().possible_values(),
            [ResolutionSlotValue::TypeObject(_)]
        ));
        assert!(matches!(
            sub_value.frontier().possible_values(),
            [ResolutionSlotValue::Runtime { .. }]
        ));

        let declared = lowered
            .transfers()
            .iter()
            .find(|transfer| {
                transfer.kind() == ResolutionTypeTransferKind::DeclaredType
                    && transfer.source_slot() == base_type.frontier().slot()
                    && transfer.rule().target_slot()
                        == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(1))
            })
            .expect("declared Base transfer");
        let observed = lowered
            .transfers()
            .iter()
            .find(|transfer| transfer.kind() == ResolutionTypeTransferKind::Assignment)
            .expect("observed Sub assignment");
        assert_eq!(
            declared.rule().value_transform(),
            TypeTransferValueTransform::ToRuntime { addressable: false }
        );
        assert_eq!(declared.source_slot(), base_type.frontier().slot());
        assert_eq!(
            declared.rule().target_slot(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(1))
        );
        assert_eq!(declared.rule().indirection_delta(), 0);
        assert_eq!(observed.source_slot(), sub_value.frontier().slot());
        assert_eq!(
            observed.rule().target_slot(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(3))
        );
        assert_eq!(
            observed.rule().value_transform(),
            TypeTransferValueTransform::Preserve
        );
        assert_eq!(observed.rule().indirection_delta(), 0);
        assert_ne!(
            base_type.frontier().possible_values()[0].ty().identity(),
            sub_value.frontier().possible_values()[0].ty().identity()
        );
        assert_eq!(
            declared.rule().completion(),
            &ResolutionCompletion::Complete
        );
        assert_eq!(
            observed.rule().completion(),
            &ResolutionCompletion::Complete
        );

        let declared_slots = lowered
            .declaration_types()
            .iter()
            .map(LoweredDeclarationTypeProperty::slot)
            .collect::<HashSet<_>>();
        assert!(declared_slots.contains(&type_slot_semantic(
            fragment(),
            ResolutionTypeSlotId::new(1)
        )));
        assert!(declared_slots.contains(&type_slot_semantic(
            fragment(),
            ResolutionTypeSlotId::new(5)
        )));
        assert!(!declared_slots.contains(&type_slot_semantic(
            fragment(),
            ResolutionTypeSlotId::new(3)
        )));
        assert!(!declared_slots.contains(&type_slot_semantic(
            fragment(),
            ResolutionTypeSlotId::new(6)
        )));
    }

    #[test]
    fn constructor_projection_uses_distinct_namespace_and_owner_scope() {
        let facts = constructor_facts();
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let constructor_reference = reference_semantic(fragment(), ResolutionSiteId::new(3));
        let constructor_definition = definition_semantic(fragment(), ResolutionSiteId::new(1));
        let owner_definition = definition_semantic(fragment(), ResolutionSiteId::new(0));
        let projection = lowered
            .projections()
            .iter()
            .find(|projection| projection.reference() == constructor_reference)
            .expect("constructor projection");
        assert_eq!(
            projection.kind(),
            BindingProjectionKind::TargetConstructorOwnerType
        );
        let owner = lowered
            .member_owners()
            .iter()
            .find(|property| property.definition() == constructor_definition)
            .expect("constructor owner property");
        assert_eq!(owner.owner_definition(), owner_definition);
        assert_eq!(owner.kind(), ResolutionMemberKind::Constructor);
        assert_eq!(owner.access(), ResolutionMemberAccess::Type);
        assert_eq!(
            owner.owner_scope_head(),
            scope_head_node(fragment(), ResolutionScopeId::new(1))
        );

        let route = lowered
            .qualified_routes()
            .iter()
            .find(|route| route.reference() == constructor_reference)
            .expect("constructor seeded route");
        assert_eq!(route.namespace(), ResolutionNamespace::Constructor);
        assert_eq!(route.precedence_ordinal(), 0);
        assert_eq!(
            route.lookup(),
            lookup_semantic(Language::Java, ResolutionNamespace::Constructor, "Sub")
        );
        assert_eq!(
            route.coarse_gap_reason(),
            gap_reason_semantic(
                fragment(),
                ResolutionSiteId::new(3),
                LoweringGapOrigin::QualifiedReference,
            )
        );
    }

    #[test]
    fn qualifier_compatibility_is_not_inferred_from_declaration_access() {
        let mut facts = constructor_facts();
        facts.names.push(name(1, "STATIC_FIELD"));
        facts
            .sites
            .push(site(5, 1, ResolutionSiteKind::ValueDeclaration, 40));
        facts.identifiers.push(identifier(
            5,
            1,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        ));
        facts.member_owners.push(ResolutionMemberOwnerFact {
            member: ResolutionSiteId::new(5),
            owner: ResolutionSiteId::new(0),
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
        });
        facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration: ResolutionSiteId::new(5),
                visibility: DeclaredVisibility::Public,
            });
        facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact {
                declaration: ResolutionSiteId::new(5),
            });
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let property = lowered
            .member_owners()
            .iter()
            .find(|property| property.kind() == ResolutionMemberKind::Field)
            .expect("static field property");
        assert_eq!(property.access(), ResolutionMemberAccess::Type);
        assert_eq!(
            property.qualifier_compatibility(),
            ResolutionMemberQualifierCompatibility::RuntimeOrType
        );
    }

    #[test]
    fn call_and_signature_rows_preserve_order_without_claiming_applicability() {
        let facts = call_applicability_facts();
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let obligation = &lowered.call_obligations()[0];
        assert_eq!(
            obligation.call(),
            call_semantic(fragment(), ResolutionSiteId::new(4))
        );
        assert_eq!(
            obligation.callee_reference(),
            reference_semantic(fragment(), ResolutionSiteId::new(3))
        );
        assert_eq!(obligation.receiver_slot(), None);
        assert_eq!(
            obligation.result_slot(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(1))
        );
        assert_eq!(
            obligation.argument_slots(),
            &[
                type_slot_semantic(fragment(), ResolutionTypeSlotId::new(4)),
                type_slot_semantic(fragment(), ResolutionTypeSlotId::new(5)),
            ]
        );
        assert_eq!(obligation.explicit_type_argument_count(), 2);
        assert_eq!(
            obligation.applicability_reason(),
            gap_reason_semantic(
                fragment(),
                ResolutionSiteId::new(3),
                LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability,),
            )
        );
        assert!(matches!(
            obligation.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    obligation.applicability_reason()
                ))
        ));

        let signature = lowered
            .callable_signatures()
            .iter()
            .find(|signature| {
                signature.definition() == definition_semantic(fragment(), ResolutionSiteId::new(1))
            })
            .expect("constructor signature");
        assert_eq!(signature.type_parameter_count(), 3);
        assert_eq!(
            signature
                .parameters()
                .iter()
                .map(LoweredCallableParameterProperty::ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(!signature.parameters()[0].repeated());
        assert!(signature.parameters()[1].repeated());
        assert_eq!(signature.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn intrinsic_seed_category_is_explicit_and_unsupported_roles_are_incomplete() {
        let mut facts = declared_and_observed_facts();
        facts
            .type_slots
            .push(slot(7, 2, ResolutionTypeSlotRole::AssignmentValue));
        facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: ResolutionTypeSlotId::new(7),
            name: ResolutionNameId::new(1),
            kind: IntrinsicTypeKind::LanguageBuiltin,
            indirection: 0,
        });
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let unsupported = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(7))
            })
            .expect("unsupported intrinsic role remains represented");
        assert!(unsupported.frontier().possible_values().is_empty());
        assert!(matches!(
            unsupported.frontier().completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn signed_pointer_delta_is_a_rule_not_a_precomputed_value() {
        let mut facts = FileResolutionFacts {
            names: vec![name(0, "T")],
            scopes: vec![scope(
                0,
                None,
                None,
                ResolutionScopeKind::CompilationUnit,
                0,
                20,
            )],
            sites: vec![site(0, 0, ResolutionSiteKind::Literal, 1)],
            type_slots: vec![
                slot(0, 0, ResolutionTypeSlotRole::ExpressionValue),
                slot(1, 0, ResolutionTypeSlotRole::AssignmentValue),
            ],
            type_transfers: vec![transfer(
                0,
                1,
                ResolutionTypeTransferKind::Assignment,
                -1,
                ResolutionTypeTransferValueTransform::Preserve,
            )],
            intrinsic_type_seeds: vec![IntrinsicTypeSeedFact {
                output: ResolutionTypeSlotId::new(0),
                name: ResolutionNameId::new(0),
                kind: IntrinsicTypeKind::LanguageBuiltin,
                indirection: 2,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_typed_resolution_facts(fragment(), Language::Go, &facts);
        let rule = lowered.transfers()[0].rule();
        assert_eq!(rule.indirection_delta(), -1);
        let input = lowered.intrinsic_seeds()[0].frontier().possible_values()[0];
        assert_eq!(input.ty().indirection(), 2);
        assert_eq!(rule.value_transform(), TypeTransferValueTransform::Preserve);
        assert_eq!(rule.completion(), &ResolutionCompletion::Complete);
        assert_eq!(
            lowered.transfers()[0].source_slot(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0))
        );
        assert_eq!(
            rule.target_slot(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(1))
        );

        facts.type_transfers[0].indirection_delta = 1;
        let incremented = lower_typed_resolution_facts(fragment(), Language::Go, &facts);
        assert_eq!(incremented.transfers()[0].rule().indirection_delta(), 1);
        assert_eq!(incremented.intrinsic_seeds(), lowered.intrinsic_seeds());
        assert_eq!(
            incremented.intrinsic_seeds()[0]
                .frontier()
                .possible_values()[0],
            input
        );
        assert_eq!(
            incremented.transfers()[0].source_slot(),
            lowered.transfers()[0].source_slot()
        );
        assert_eq!(
            incremented.transfers()[0].rule().target_slot(),
            rule.target_slot()
        );
        assert_eq!(
            incremented.transfers()[0].rule().value_transform(),
            TypeTransferValueTransform::Preserve
        );
        assert_eq!(
            incremented.transfers()[0].rule().completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[test]
    fn complete_no_value_transform_is_preserved_as_a_rule() {
        let mut facts = declared_and_observed_facts();
        let declared = facts
            .type_transfers
            .iter_mut()
            .find(|fact| fact.kind == ResolutionTypeTransferKind::DeclaredType)
            .expect("declared type transfer fixture");
        declared.value_transform = ResolutionTypeTransferValueTransform::ToNoValue;
        declared.indirection_delta = 0;
        let expected_source = type_slot_semantic(fragment(), declared.input);
        let expected_target = type_slot_semantic(fragment(), declared.output);

        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let transfer = lowered
            .transfers()
            .iter()
            .find(|transfer| {
                transfer.kind() == ResolutionTypeTransferKind::DeclaredType
                    && transfer.source_slot() == expected_source
                    && transfer.rule().target_slot() == expected_target
            })
            .expect("lowered declared type transfer");
        let rule = transfer.rule();
        assert_eq!(
            rule.value_transform(),
            TypeTransferValueTransform::ToNoValue
        );
        assert_eq!(rule.indirection_delta(), 0);
        assert_eq!(rule.completion(), &ResolutionCompletion::Complete);
        assert_eq!(transfer.source_slot(), expected_source);
        assert_eq!(rule.target_slot(), expected_target);
        let seed = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| seed.frontier().slot() == expected_source)
            .expect("typed seed");
        assert!(matches!(
            seed.frontier().possible_values(),
            [ResolutionSlotValue::TypeObject(_)]
        ));
    }

    #[test]
    fn implicit_constructor_and_hierarchy_gaps_are_owned_properties() {
        let mut facts = hierarchy_facts();
        facts.declaration_visibilities[0].visibility = DeclaredVisibility::PackagePrivate;
        facts.gaps.push(ResolutionGapFact {
            site: ResolutionSiteId::new(0),
            kind: ResolutionGapKind::UnsupportedVisibility,
        });
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let subtype = definition_semantic(fragment(), ResolutionSiteId::new(0));
        let implicit = lowered
            .property_gaps()
            .iter()
            .find(|gap| gap.kind() == ResolutionGapKind::ImplicitConstructor)
            .expect("implicit constructor property gap");
        assert_eq!(implicit.definition(), subtype);
        assert_eq!(
            implicit.frontier(),
            site_type_frontier_semantic(fragment(), ResolutionSiteId::new(0))
        );
        let hierarchy = lowered
            .property_gaps()
            .iter()
            .find(|gap| gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal)
            .expect("hierarchy property gap");
        assert_eq!(hierarchy.definition(), subtype);
        assert_eq!(
            hierarchy.frontier(),
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0))
        );
        let supertype = lowered.supertypes()[0];
        assert_eq!(supertype.definition(), subtype);
        assert_eq!(
            supertype.reference(),
            reference_semantic(fragment(), ResolutionSiteId::new(1))
        );
        assert_eq!(supertype.frontier(), hierarchy.frontier());
        let visibility = lowered
            .property_gaps()
            .iter()
            .find(|gap| gap.kind() == ResolutionGapKind::UnsupportedVisibility)
            .expect("visibility property gap");
        assert_eq!(visibility.definition(), subtype);
        assert_eq!(
            visibility.frontier(),
            site_type_frontier_semantic(fragment(), ResolutionSiteId::new(0))
        );
    }

    #[test]
    fn nested_type_lookup_and_enclosing_instance_are_separate_properties() {
        let facts = nested_constructor_facts();
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let nested = lowered
            .member_owners()
            .iter()
            .find(|owner| owner.kind() == ResolutionMemberKind::NestedType)
            .expect("nested type lookup property");
        let requirement = lowered.construction_requirements()[0];
        assert_eq!(nested.access(), ResolutionMemberAccess::Type);
        assert_eq!(
            nested.qualifier_compatibility(),
            ResolutionMemberQualifierCompatibility::TypeOnly
        );
        assert_eq!(nested.definition(), requirement.definition());
        assert_eq!(
            nested.owner_definition(),
            requirement.required_owner_definition()
        );
    }

    #[test]
    fn input_row_permutation_preserves_the_complete_typed_artifact() {
        let facts = call_applicability_facts();
        let expected = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let mut permuted = facts.clone();
        permuted.names.reverse();
        permuted.scopes.reverse();
        permuted.sites.reverse();
        permuted.identifiers.reverse();
        permuted.binders.reverse();
        permuted.type_slots.reverse();
        permuted.declaration_type_slots.reverse();
        permuted.binding_projections.reverse();
        permuted.type_transfers.reverse();
        permuted.intrinsic_type_seeds.reverse();
        permuted.calls.reverse();
        permuted.call_arguments.reverse();
        permuted.callable_signatures.reverse();
        permuted.callable_parameters.reverse();
        permuted.member_owners.reverse();
        permuted.supertypes.reverse();
        permuted.construction_requirements.reverse();
        permuted.gaps.reverse();
        assert_eq!(
            lower_typed_resolution_facts(fragment(), Language::Java, &permuted),
            expected
        );
    }

    #[test]
    #[should_panic(expected = "unknown resolution type slot")]
    fn malformed_projection_slot_is_rejected_at_construction() {
        let mut facts = hierarchy_facts();
        facts.binding_projections[0].output = ResolutionTypeSlotId::new(99);
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    #[should_panic(expected = "multiple output producers")]
    fn intrinsic_and_projection_cannot_produce_the_same_slot() {
        let mut facts = hierarchy_facts();
        facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: ResolutionTypeSlotId::new(0),
            name: ResolutionNameId::new(1),
            kind: IntrinsicTypeKind::LanguageBuiltin,
            indirection: 0,
        });
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    #[should_panic(expected = "multiple output producers")]
    fn projection_and_transfer_cannot_produce_the_same_slot() {
        let mut facts = constructor_facts();
        facts.type_transfers.push(transfer(
            0,
            1,
            ResolutionTypeTransferKind::Construction,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        ));
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    #[should_panic(expected = "one declaration type slot per (definition, role)")]
    fn declaration_definition_role_has_one_type_slot() {
        let mut facts = declared_and_observed_facts();
        facts
            .type_slots
            .push(slot(7, 1, ResolutionTypeSlotRole::DeclaredValue));
        facts.declaration_type_slots.push(DeclarationTypeSlotFact {
            declaration: ResolutionSiteId::new(1),
            slot: ResolutionTypeSlotId::new(7),
            role: DeclarationTypeRole::Value,
        });
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    #[should_panic(expected = "has no owning subtype property")]
    fn orphan_hierarchy_gap_is_rejected_at_construction() {
        let mut facts = hierarchy_facts();
        facts.supertypes.clear();
        let _ = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    fn artifact_never_confuses_unresolved_references_with_definition_targets() {
        let mut facts = constructor_facts();
        let hierarchy = hierarchy_facts();
        facts.names.push(name(1, "Base"));
        facts
            .sites
            .push(site(5, 0, ResolutionSiteKind::TypeReference, 95));
        facts.identifiers.push(identifier(
            5,
            1,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            None,
        ));
        facts
            .type_slots
            .push(slot(2, 5, ResolutionTypeSlotRole::TargetTypeIdentity));
        facts.binding_projections.push(BindingProjectionFact {
            reference: ResolutionSiteId::new(5),
            output: ResolutionTypeSlotId::new(2),
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
        facts.supertypes = vec![ResolutionSupertypeFact {
            subtype: ResolutionSiteId::new(0),
            supertype_reference: ResolutionSiteId::new(5),
            supertype_slot: ResolutionTypeSlotId::new(2),
            kind: hierarchy.supertypes[0].kind,
        }];
        let lowered = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let definitions = lowered
            .member_scopes()
            .iter()
            .map(LoweredMemberScopeProperty::definition)
            .chain(
                lowered
                    .member_owners()
                    .iter()
                    .map(LoweredMemberOwnerProperty::definition),
            )
            .collect::<HashSet<_>>();
        assert!(
            lowered
                .projections()
                .iter()
                .all(|projection| !definitions.contains(&projection.reference()))
        );
        assert!(
            lowered
                .qualified_routes()
                .iter()
                .all(|route| !definitions.contains(&route.reference()))
        );
        assert!(
            lowered
                .call_obligations()
                .iter()
                .all(|obligation| !definitions.contains(&obligation.callee_reference()))
        );
        assert!(
            lowered
                .supertypes()
                .iter()
                .all(|property| !definitions.contains(&property.reference()))
        );
    }
}
