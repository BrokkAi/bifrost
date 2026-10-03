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
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionBinderKind, ResolutionCallArgumentFact, ResolutionCallFact,
    ResolutionCallTypeArgumentFact, ResolutionCallableParameterFact,
    ResolutionCallableReceiverForm, ResolutionCallableResultTypeFact,
    ResolutionCallableResultTypeParameterFact, ResolutionCallableSignatureFact,
    ResolutionConstructionRequirementFact, ResolutionConstructionRequirementKind,
    ResolutionDeclaredTypeRelationKind, ResolutionEngineRuleKind, ResolutionGapKind,
    ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeInheritance,
    ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
    ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeComponentFact,
    ResolutionTypeComponentKind, ResolutionTypeConstructorKind, ResolutionTypeSlotFact,
    ResolutionTypeSlotId, ResolutionTypeSlotRole, ResolutionTypeTransferFact,
    ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

use crate::hash::{HashMap, HashSet};

use super::common_fact_lowering::{LoweredDeferredMemberOwner, member_lookup_namespace};
use super::fact_lowering::{
    LoweringGapOrigin, definition_semantic, definition_semantic_identity, gap_reason_semantic,
    gap_reason_semantic_identity, lookup_routes, lookup_semantic, mounted_site_semantic,
    reference_node_identity, reference_semantic, reference_semantic_identity, scope_head_node,
    scope_head_node_identity, site_type_frontier_semantic, site_type_frontier_semantic_identity,
    type_slot_semantic, type_slot_semantic_identity,
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

/// One persisted structural type component edge. Both endpoints are blob
/// local typed slots; the selected engine reads these rows only for a
/// container identity reached by its current query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredTypeComponent {
    container: SemanticId,
    constructor: ResolutionTypeConstructorKind,
    kind: ResolutionTypeComponentKind,
    component: SemanticId,
}

impl LoweredTypeComponent {
    pub const fn new(
        container: SemanticId,
        constructor: ResolutionTypeConstructorKind,
        kind: ResolutionTypeComponentKind,
        component: SemanticId,
    ) -> Self {
        Self {
            container,
            constructor,
            kind,
            component,
        }
    }

    pub const fn container(&self) -> SemanticId {
        self.container
    }

    pub const fn constructor(&self) -> ResolutionTypeConstructorKind {
        self.constructor
    }

    pub const fn kind(&self) -> ResolutionTypeComponentKind {
        self.kind
    }

    pub const fn component(&self) -> SemanticId {
        self.component
    }
}

/// The declared underlying syntax slot of one named type declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredUnderlyingType {
    definition: SemanticId,
    slot: SemanticId,
}

impl LoweredUnderlyingType {
    pub const fn new(definition: SemanticId, slot: SemanticId) -> Self {
        Self { definition, slot }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }
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
    spelling: Box<str>,
    frontier: TypedFrontierState,
}

impl LoweredIntrinsicSeed {
    pub fn new(
        kind: IntrinsicTypeKind,
        spelling: impl Into<Box<str>>,
        frontier: TypedFrontierState,
    ) -> Self {
        let spelling = spelling.into();
        assert!(
            !spelling.is_empty(),
            "an intrinsic type seed must retain a nonempty spelling"
        );
        Self {
            kind,
            spelling,
            frontier,
        }
    }

    pub const fn kind(&self) -> IntrinsicTypeKind {
        self.kind
    }

    pub fn spelling(&self) -> &str {
        &self.spelling
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
    type_identity_reference: Option<(SemanticId, BindingNodeId)>,
}

impl LoweredTypedFrontier {
    pub const fn new(slot: SemanticId, role: ResolutionTypeSlotRole) -> Self {
        Self {
            slot,
            role,
            type_identity_reference: None,
        }
    }

    /// Observe the evaluated identity without installing another output producer.
    pub fn with_type_identity_reference(
        mut self,
        reference: SemanticId,
        node: BindingNodeId,
    ) -> Self {
        assert_eq!(self.role, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.type_identity_reference = Some((reference, node));
        self
    }

    pub const fn type_identity_reference(&self) -> Option<(SemanticId, BindingNodeId)> {
        self.type_identity_reference
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
/// `lookup` and `namespace` select typed members; `source_lookup` retains the
/// lexical demand used by root routes and reexports before member selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweredQualifiedSeededRoute {
    reference: SemanticId,
    qualifier_slot: SemanticId,
    lookup: SemanticId,
    namespace: ResolutionNamespace,
    source_lookup: SemanticId,
    precedence_ordinal: u32,
    projection_output_slot: SemanticId,
    projection_kind: BindingProjectionKind,
    coarse_gap_reason: SemanticId,
    open_member_surface: bool,
}

impl LoweredQualifiedSeededRoute {
    #[cfg(any(test, feature = "test-support"))]
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
        Self::new_with_source_lookup(
            reference,
            qualifier_slot,
            lookup,
            namespace,
            lookup,
            precedence_ordinal,
            projection_output_slot,
            projection_kind,
            coarse_gap_reason,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn new_with_source_lookup(
        reference: SemanticId,
        qualifier_slot: SemanticId,
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        source_lookup: SemanticId,
        precedence_ordinal: u32,
        projection_output_slot: SemanticId,
        projection_kind: BindingProjectionKind,
        coarse_gap_reason: SemanticId,
        open_member_surface: bool,
    ) -> Self {
        Self {
            reference,
            qualifier_slot,
            lookup,
            namespace,
            source_lookup,
            precedence_ordinal,
            projection_output_slot,
            projection_kind,
            coarse_gap_reason,
            open_member_surface,
        }
    }

    /// The producer's statement that this owner's member surface is not
    /// closed, so a hierarchy walk reaching no declaring owner proves nothing.
    pub const fn open_member_surface(&self) -> bool {
        self.open_member_surface
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

    /// Source-owned lexical demand, distinct from the typed member selector.
    pub const fn source_lookup(&self) -> SemanticId {
        self.source_lookup
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

    /// Rust method values use a type path, not a bound runtime receiver.
    pub const fn requires_type_qualifier(&self) -> bool {
        matches!(self.namespace, ResolutionNamespace::Callable)
            && matches!(
                self.projection_kind,
                BindingProjectionKind::TargetDeclaredValueType
            )
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
    extra_result_slots: Box<[SemanticId]>,
    argument_slots: Box<[SemanticId]>,
    /// The explicit type arguments' value slots, in position order.
    type_argument_slots: Box<[SemanticId]>,
    /// The value slots of the type arguments written on the path's type
    /// segment (`Wrapper::<Square>::make()`), in position order.
    owner_type_argument_slots: Box<[SemanticId]>,
    /// The identity slot of that type segment's reference, present exactly
    /// when the segment writes arguments.
    owner_type_segment: Option<SemanticId>,
    /// The value slot of the type the call's context expects its result to
    /// have (a `let` annotation), when there is one.
    expected_result_slot: Option<SemanticId>,
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
            extra_result_slots: Box::new([]),
            argument_slots: argument_slots.into(),
            type_argument_slots: Box::new([]),
            owner_type_argument_slots: Box::new([]),
            owner_type_segment: None,
            expected_result_slot: None,
            eligible_rules: eligible_rules.into(),
            explicit_type_argument_count,
            applicability_reason,
            completion,
        }
    }

    /// This obligation with its explicit type arguments' value slots.
    pub fn with_type_argument_slots(mut self, slots: impl Into<Box<[SemanticId]>>) -> Self {
        self.type_argument_slots = slots.into();
        self
    }

    /// This obligation with the additional call result slots, in result order
    /// after `result_slot` (which is ordinal zero).
    pub fn with_extra_result_slots(mut self, slots: impl Into<Box<[SemanticId]>>) -> Self {
        self.extra_result_slots = slots.into();
        self
    }

    pub fn extra_result_slots(&self) -> &[SemanticId] {
        &self.extra_result_slots
    }

    pub fn type_argument_slots(&self) -> &[SemanticId] {
        &self.type_argument_slots
    }

    /// This obligation with its path type segment's identity slot and the
    /// value slots of the type arguments it writes.
    pub fn with_owner_type_arguments(
        mut self,
        segment: Option<SemanticId>,
        slots: impl Into<Box<[SemanticId]>>,
    ) -> Self {
        let slots = slots.into();
        assert_eq!(
            segment.is_some(),
            !slots.is_empty(),
            "a type segment's arguments come with its identity slot"
        );
        self.owner_type_segment = segment;
        self.owner_type_argument_slots = slots;
        self
    }

    pub const fn owner_type_segment(&self) -> Option<SemanticId> {
        self.owner_type_segment
    }

    pub fn owner_type_argument_slots(&self) -> &[SemanticId] {
        &self.owner_type_argument_slots
    }

    /// This obligation with the value slot of its expected result type.
    pub fn with_expected_result_slot(mut self, slot: Option<SemanticId>) -> Self {
        self.expected_result_slot = slot;
        self
    }

    pub const fn expected_result_slot(&self) -> Option<SemanticId> {
        self.expected_result_slot
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

/// One parameter whose argument decides the callable's result type: the
/// argument's type, adjusted by the result's layers minus the parameter's.
/// See `ResolutionCallableResultBindingFact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoweredCallableResultBinding {
    ordinal: u32,
    indirection_delta: i64,
    reference_indirection_delta: i64,
}

impl LoweredCallableResultBinding {
    pub const fn new(
        ordinal: u32,
        indirection_delta: i64,
        reference_indirection_delta: i64,
    ) -> Self {
        Self {
            ordinal,
            indirection_delta,
            reference_indirection_delta,
        }
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn indirection_delta(&self) -> i64 {
        self.indirection_delta
    }

    pub const fn reference_indirection_delta(&self) -> i64 {
        self.reference_indirection_delta
    }
}

/// The target-independent local signature indexed by callable definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredCallableSignatureProperty {
    definition: SemanticId,
    type_parameter_count: u32,
    parameters: Box<[LoweredCallableParameterProperty]>,
    result_types: Box<[LoweredCallableResultTypeProperty]>,
    /// The parameters whose arguments decide the result type, by ordinal.
    result_bindings: Box<[LoweredCallableResultBinding]>,
    /// How the method takes its receiver, when it declares one in a standard
    /// form.
    receiver: Option<ResolutionCallableReceiverForm>,
    /// The result's own type parameter position and layers, when the result
    /// is one of this callable's type parameters.
    result_type_parameter: Option<LoweredCallableResultBinding>,
    /// The position among the enclosing impl target's type arguments, and
    /// the layers, when the result is one of the impl's type parameters.
    result_owner_type_parameter: Option<LoweredCallableResultBinding>,
    completion: ResolutionCompletion,
}

/// One position in the declared result tuple of a callable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredCallableResultTypeProperty {
    ordinal: u32,
    slot: SemanticId,
}

impl LoweredCallableResultTypeProperty {
    pub const fn new(ordinal: u32, slot: SemanticId) -> Self {
        Self { ordinal, slot }
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }
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
            Box::new([]),
            Box::new([]),
            None,
            completion,
            &mut never_cancelled,
        ) else {
            unreachable!("the never-cancelled signature poll returned cancellation")
        };
        signature
    }

    /// This signature with its declaration's ordered result type slots.
    pub fn with_result_types(
        mut self,
        result_types: impl Into<Box<[LoweredCallableResultTypeProperty]>>,
    ) -> Self {
        let mut result_types = result_types.into().into_vec();
        result_types.sort_unstable_by_key(|result| result.ordinal);
        assert!(
            result_types
                .iter()
                .enumerate()
                .all(|(ordinal, result)| usize::try_from(result.ordinal).ok() == Some(ordinal)),
            "callable result type ordinals must be contiguous from zero: {result_types:?}"
        );
        self.result_types = result_types.into_boxed_slice();
        self
    }

    pub fn result_types(&self) -> &[LoweredCallableResultTypeProperty] {
        &self.result_types
    }

    /// This signature with the receiver form its method declares.
    pub fn with_receiver(mut self, receiver: Option<ResolutionCallableReceiverForm>) -> Self {
        self.receiver = receiver;
        self
    }

    /// This signature with the position of the type parameter its result is,
    /// among its non-lifetime generic parameters, and the result's layers.
    pub fn with_result_type_parameter(
        mut self,
        result_type_parameter: Option<LoweredCallableResultBinding>,
    ) -> Self {
        self.result_type_parameter = result_type_parameter;
        self
    }

    pub const fn result_type_parameter(&self) -> Option<LoweredCallableResultBinding> {
        self.result_type_parameter
    }

    /// This signature with the position of the impl type parameter its
    /// result is, among the impl target type's non-lifetime arguments, and the
    /// result's layers.
    pub fn with_result_owner_type_parameter(
        mut self,
        result_owner_type_parameter: Option<LoweredCallableResultBinding>,
    ) -> Self {
        assert!(
            result_owner_type_parameter.is_none() || self.result_type_parameter.is_none(),
            "a result is one type parameter, the callable's own or its impl's"
        );
        self.result_owner_type_parameter = result_owner_type_parameter;
        self
    }

    pub const fn result_owner_type_parameter(&self) -> Option<LoweredCallableResultBinding> {
        self.result_owner_type_parameter
    }

    /// This signature with the parameters whose arguments decide its result.
    pub fn with_result_bindings(
        self,
        bindings: impl Into<Box<[LoweredCallableResultBinding]>>,
    ) -> Self {
        let mut bindings = bindings.into().into_vec();
        bindings.sort_unstable_by_key(|binding| binding.ordinal);
        let result_type_parameter = self.result_type_parameter;
        let result_owner_type_parameter = self.result_owner_type_parameter;
        let Some(signature) = Self::from_canonical_parts_with_poll(
            self.definition,
            self.type_parameter_count,
            self.parameters,
            self.result_types,
            bindings.into_boxed_slice(),
            self.receiver,
            self.completion,
            &mut never_cancelled,
        ) else {
            unreachable!("the never-cancelled signature poll returned cancellation")
        };
        signature
            .with_result_type_parameter(result_type_parameter)
            .with_result_owner_type_parameter(result_owner_type_parameter)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_canonical_parts_with_poll<P>(
        definition: SemanticId,
        type_parameter_count: u32,
        parameters: Box<[LoweredCallableParameterProperty]>,
        result_types: Box<[LoweredCallableResultTypeProperty]>,
        result_bindings: Box<[LoweredCallableResultBinding]>,
        receiver: Option<ResolutionCallableReceiverForm>,
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
        assert!(
            result_bindings
                .windows(2)
                .all(|pair| pair[0].ordinal < pair[1].ordinal),
            "callable {definition:?} result bindings are distinct and ordered: {result_bindings:?}"
        );
        assert!(
            result_bindings.iter().all(|binding| {
                parameters
                    .get(usize::try_from(binding.ordinal).expect("u32 ordinal fits usize"))
                    .is_some_and(|parameter| !parameter.repeated)
            }),
            "callable {definition:?} result bindings name ordinary parameters: {result_bindings:?}"
        );
        assert!(
            result_types
                .iter()
                .enumerate()
                .all(|(ordinal, result)| { usize::try_from(result.ordinal).ok() == Some(ordinal) }),
            "callable {definition:?} result type ordinals must be contiguous: {result_types:?}"
        );
        Some(Self {
            definition,
            type_parameter_count,
            parameters,
            result_types,
            result_bindings,
            receiver,
            result_type_parameter: None,
            result_owner_type_parameter: None,
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
        let mut result_types = Vec::with_capacity(self.result_types.len());
        for &result in self.result_types.iter() {
            if cancelled() {
                return None;
            }
            result_types.push(result);
        }
        Self::from_canonical_parts_with_poll(
            self.definition,
            self.type_parameter_count,
            parameters.into_boxed_slice(),
            result_types.into_boxed_slice(),
            self.result_bindings.clone(),
            self.receiver,
            clone_completion_with_poll(&self.completion, cancelled)?,
            cancelled,
        )
        .map(|signature| {
            signature
                .with_result_type_parameter(self.result_type_parameter)
                .with_result_owner_type_parameter(self.result_owner_type_parameter)
        })
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

    pub fn result_bindings(&self) -> &[LoweredCallableResultBinding] {
        &self.result_bindings
    }

    pub const fn receiver(&self) -> Option<ResolutionCallableReceiverForm> {
        self.receiver
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
    type_components: Vec<LoweredTypeComponent>,
    underlying_types: Vec<LoweredUnderlyingType>,
    intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
    projections: Vec<LoweredBindingProjection>,
    qualified_routes: Vec<LoweredQualifiedSeededRoute>,
    declaration_types: Vec<LoweredDeclarationTypeProperty>,
    declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
    member_scopes: Vec<LoweredMemberScopeProperty>,
    member_owners: Vec<LoweredMemberOwnerProperty>,
    deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
    construction_requirements: Vec<LoweredConstructionRequirementProperty>,
    supertypes: Vec<LoweredSupertypeProperty>,
    property_gaps: Vec<LoweredDefinitionPropertyGap>,
    call_obligations: Vec<LoweredCallApplicabilityObligation>,
    callable_signatures: Vec<LoweredCallableSignatureProperty>,
}

impl LoweredTypedFragment {
    pub(crate) fn empty(fragment: BindingFragmentId, language: Language) -> Self {
        Self::new_with_type_relations(
            fragment,
            language,
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
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    pub(crate) fn append_selected_macro_fragment(&mut self, added: Self) {
        assert_eq!(
            (self.fragment, self.language),
            (added.fragment, added.language)
        );
        self.frontiers.extend(added.frontiers);
        self.transfers.extend(added.transfers);
        self.type_components.extend(added.type_components);
        self.underlying_types.extend(added.underlying_types);
        self.intrinsic_seeds.extend(added.intrinsic_seeds);
        self.projections.extend(added.projections);
        self.qualified_routes.extend(added.qualified_routes);
        self.declaration_types.extend(added.declaration_types);
        self.declaration_visibilities
            .extend(added.declaration_visibilities);
        self.member_scopes.extend(added.member_scopes);
        self.member_owners.extend(added.member_owners);
        self.deferred_member_owners
            .extend(added.deferred_member_owners);
        self.construction_requirements
            .extend(added.construction_requirements);
        self.supertypes.extend(added.supertypes);
        self.property_gaps.extend(added.property_gaps);
        self.call_obligations.extend(added.call_obligations);
        self.callable_signatures.extend(added.callable_signatures);
        *self = Self::new_with_type_relations(
            self.fragment,
            self.language,
            std::mem::take(&mut self.frontiers),
            std::mem::take(&mut self.transfers),
            std::mem::take(&mut self.type_components),
            std::mem::take(&mut self.underlying_types),
            std::mem::take(&mut self.intrinsic_seeds),
            std::mem::take(&mut self.projections),
            std::mem::take(&mut self.qualified_routes),
            std::mem::take(&mut self.declaration_types),
            std::mem::take(&mut self.declaration_visibilities),
            std::mem::take(&mut self.member_scopes),
            std::mem::take(&mut self.member_owners),
            std::mem::take(&mut self.deferred_member_owners),
            std::mem::take(&mut self.construction_requirements),
            std::mem::take(&mut self.supertypes),
            std::mem::take(&mut self.property_gaps),
            std::mem::take(&mut self.call_obligations),
            std::mem::take(&mut self.callable_signatures),
        );
    }

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
        frontiers: Vec<LoweredTypedFrontier>,
        transfers: Vec<LoweredTypeTransfer>,
        intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
        projections: Vec<LoweredBindingProjection>,
        qualified_routes: Vec<LoweredQualifiedSeededRoute>,
        declaration_types: Vec<LoweredDeclarationTypeProperty>,
        declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
        member_scopes: Vec<LoweredMemberScopeProperty>,
        member_owners: Vec<LoweredMemberOwnerProperty>,
        deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
        construction_requirements: Vec<LoweredConstructionRequirementProperty>,
        supertypes: Vec<LoweredSupertypeProperty>,
        property_gaps: Vec<LoweredDefinitionPropertyGap>,
        call_obligations: Vec<LoweredCallApplicabilityObligation>,
        callable_signatures: Vec<LoweredCallableSignatureProperty>,
    ) -> Self {
        Self::new_with_type_relations(
            fragment,
            language,
            frontiers,
            transfers,
            Vec::new(),
            Vec::new(),
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
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_type_relations(
        fragment: BindingFragmentId,
        language: Language,
        mut frontiers: Vec<LoweredTypedFrontier>,
        mut transfers: Vec<LoweredTypeTransfer>,
        mut type_components: Vec<LoweredTypeComponent>,
        mut underlying_types: Vec<LoweredUnderlyingType>,
        mut intrinsic_seeds: Vec<LoweredIntrinsicSeed>,
        mut projections: Vec<LoweredBindingProjection>,
        mut qualified_routes: Vec<LoweredQualifiedSeededRoute>,
        mut declaration_types: Vec<LoweredDeclarationTypeProperty>,
        mut declaration_visibilities: Vec<LoweredDeclarationVisibilityProperty>,
        mut member_scopes: Vec<LoweredMemberScopeProperty>,
        mut member_owners: Vec<LoweredMemberOwnerProperty>,
        mut deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
        mut construction_requirements: Vec<LoweredConstructionRequirementProperty>,
        mut supertypes: Vec<LoweredSupertypeProperty>,
        mut property_gaps: Vec<LoweredDefinitionPropertyGap>,
        mut call_obligations: Vec<LoweredCallApplicabilityObligation>,
        mut callable_signatures: Vec<LoweredCallableSignatureProperty>,
    ) -> Self {
        assert_ne!(language, Language::None, "typed fragment needs a language");
        frontiers.sort_by_key(frontier_sort_key);
        transfers.sort_by_key(transfer_sort_key);
        type_components.sort_unstable();
        underlying_types.sort_unstable();
        intrinsic_seeds.sort_by_key(intrinsic_sort_key);
        projections.sort_by_key(projection_sort_key);
        qualified_routes.sort_by_key(qualified_route_sort_key);
        declaration_types.sort_by_key(declaration_type_sort_key);
        declaration_visibilities.sort_unstable();
        member_scopes.sort_unstable();
        member_owners.sort_by_key(member_owner_sort_key);
        deferred_member_owners.sort_unstable_by_key(|property| {
            (
                property.owner_frontier(),
                property.lookup(),
                property.definition(),
                property.kind(),
                property.access(),
                property.qualifier_compatibility(),
            )
        });
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
        let mut constructors_by_container = HashMap::default();
        let mut component_kinds_by_container = HashSet::default();
        for component in &self.type_components {
            assert_eq!(
                inventory.get(&component.container),
                Some(&ResolutionTypeSlotRole::TargetTypeIdentity),
                "a structural container must have a target type-identity frontier"
            );
            assert_eq!(
                inventory.get(&component.component),
                Some(&ResolutionTypeSlotRole::TargetTypeIdentity),
                "a structural component must have a target type-identity frontier"
            );
            if let Some(prior) =
                constructors_by_container.insert(component.container, component.constructor)
            {
                assert_eq!(
                    prior, component.constructor,
                    "one structural type slot has one constructor kind"
                );
            }
            assert!(
                component_kinds_by_container.insert((component.container, component.kind)),
                "one structural type slot has one component of each kind"
            );
            assert!(matches!(
                (component.constructor, component.kind),
                (
                    ResolutionTypeConstructorKind::Sequence
                        | ResolutionTypeConstructorKind::Channel,
                    ResolutionTypeComponentKind::Element
                ) | (
                    ResolutionTypeConstructorKind::Map,
                    ResolutionTypeComponentKind::Key | ResolutionTypeComponentKind::Value
                )
            ));
        }
        assert!(
            self.underlying_types
                .iter()
                .all(|relation| inventory.get(&relation.slot)
                    == Some(&ResolutionTypeSlotRole::TargetTypeIdentity)),
            "a declared underlying type is an indexed target type-identity frontier"
        );
        assert!(
            self.underlying_types
                .windows(2)
                .all(|pair| pair[0].definition != pair[1].definition),
            "one declared underlying type relation per type definition"
        );
        assert_unique_lowered_rows(self);
        validate_lowered_output_producers(
            &self.transfers,
            &self.intrinsic_seeds,
            &self.projections,
        );

        let identity_outputs = self
            .transfers
            .iter()
            .filter(|transfer| transfer.kind() == ResolutionTypeTransferKind::TypeIdentity)
            .map(|transfer| transfer.rule().target_slot())
            .collect::<HashSet<_>>();
        let projected_outputs = self
            .projections
            .iter()
            .map(|projection| projection.output_slot())
            .collect::<HashSet<_>>();
        let mut observed_references = HashSet::default();
        for frontier in &self.frontiers {
            if let Some((reference, _)) = frontier.type_identity_reference() {
                assert_eq!(frontier.role(), ResolutionTypeSlotRole::TargetTypeIdentity);
                assert!(
                    identity_outputs.contains(&frontier.slot()),
                    "an observed identity must be transfer-owned"
                );
                assert!(
                    !projected_outputs.contains(&frontier.slot()),
                    "an observed identity frontier has no binding projection"
                );
                assert!(
                    observed_references.insert(reference),
                    "one identity observation per reference"
                );
            }
        }

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
            assert!(
                transfer_accepts_output_role(transfer.kind, output_role),
                "type-transfer kind and output role disagree"
            );
            match transfer.kind {
                ResolutionTypeTransferKind::TypeIdentity
                | ResolutionTypeTransferKind::TypeUnion
                | ResolutionTypeTransferKind::TypeAlias => assert_eq!(
                    source_role,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                    "type-identity transfer input must retain a type object"
                ),
                ResolutionTypeTransferKind::DeclaredType => assert_eq!(
                    source_role,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                    "declared-type transfer input must retain a type object"
                ),
                ResolutionTypeTransferKind::Initialization => assert!(
                    matches!(
                        source_role,
                        ResolutionTypeSlotRole::CallResult
                            | ResolutionTypeSlotRole::ExpressionValue
                    ),
                    "initialization transfer input must retain the initializer's produced value"
                ),
                ResolutionTypeTransferKind::ComponentElement
                | ResolutionTypeTransferKind::ComponentKey
                | ResolutionTypeTransferKind::ComponentValue => assert!(
                    matches!(
                        source_role,
                        ResolutionTypeSlotRole::TargetTypeIdentity
                            | ResolutionTypeSlotRole::DeclaredValue
                            | ResolutionTypeSlotRole::ExpressionValue
                            | ResolutionTypeSlotRole::CallResult
                    ),
                    "component transfer input must retain a resolved type or value"
                ),
                ResolutionTypeTransferKind::Unwrap => assert!(
                    matches!(
                        source_role,
                        ResolutionTypeSlotRole::CallResult
                            | ResolutionTypeSlotRole::ExpressionValue
                    ),
                    "unwrap transfer input must retain the unwrapped operand's value"
                ),
                ResolutionTypeTransferKind::Assignment
                | ResolutionTypeTransferKind::Construction
                | ResolutionTypeTransferKind::Receiver
                | ResolutionTypeTransferKind::Argument
                | ResolutionTypeTransferKind::Return
                | ResolutionTypeTransferKind::UnaryIndirection
                | ResolutionTypeTransferKind::AddressOf => {}
            }
            if transfer.kind == ResolutionTypeTransferKind::AddressOf {
                validate_address_of_transfer(
                    transfer.rule.indirection_delta(),
                    transfer.rule.reference_indirection_delta(),
                    transfer.rule.value_transform(),
                );
                assert!(
                    matches!(
                        source_role,
                        ResolutionTypeSlotRole::ExpressionValue
                            | ResolutionTypeSlotRole::CallResult
                    ),
                    "address-of requires an expression operand"
                );
            }
            if matches!(
                transfer.kind,
                ResolutionTypeTransferKind::TypeIdentity | ResolutionTypeTransferKind::TypeUnion
            ) {
                assert_eq!(
                    (
                        transfer.rule.indirection_delta(),
                        transfer.rule.reference_indirection_delta(),
                    ),
                    (0, 0),
                    "type-identity transfer must preserve indirection"
                );
                assert_eq!(
                    transfer.rule.value_transform(),
                    TypeTransferValueTransform::Preserve,
                    "type-identity transfer must preserve its type-object category"
                );
            }
            if transfer.kind == ResolutionTypeTransferKind::TypeAlias {
                assert!(transfer.rule.indirection_delta() >= 0);
                assert!(
                    (0..=transfer.rule.indirection_delta())
                        .contains(&transfer.rule.reference_indirection_delta())
                );
                assert_eq!(
                    transfer.rule.value_transform(),
                    TypeTransferValueTransform::Preserve
                );
            }
            if transfer.kind == ResolutionTypeTransferKind::Initialization {
                assert_eq!(
                    (
                        transfer.rule.indirection_delta(),
                        transfer.rule.reference_indirection_delta(),
                    ),
                    (0, 0),
                    "initialization transfer must preserve indirection"
                );
                assert!(
                    matches!(
                        transfer.rule.value_transform(),
                        TypeTransferValueTransform::Preserve
                            | TypeTransferValueTransform::AddressableRuntimeOnly
                    ),
                    "initialization must preserve runtime category or admit an addressable runtime value"
                );
            }
            if transfer.kind == ResolutionTypeTransferKind::Unwrap {
                assert_eq!(
                    (
                        transfer.rule.indirection_delta(),
                        transfer.rule.reference_indirection_delta(),
                    ),
                    (-1, 0),
                    "unwrap transfer must remove exactly one unproven indirection layer"
                );
                assert_eq!(
                    transfer.rule.value_transform(),
                    TypeTransferValueTransform::Preserve,
                    "unwrap transfer must preserve its runtime value category"
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
                match property.role {
                    DeclarationTypeRole::Identity | DeclarationTypeRole::NominalIdentity =>
                        ResolutionTypeSlotRole::TargetTypeIdentity,
                    _ => ResolutionTypeSlotRole::DeclaredValue,
                },
                "declaration type property must retain its declared category"
            );
        }
        let parameter_declarations = self
            .declaration_types
            .iter()
            .filter(|property| property.role == DeclarationTypeRole::Parameter)
            .map(|property| (property.definition, property.slot))
            .collect::<HashMap<_, _>>();
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
            let member_definitions = self
                .member_owners
                .iter()
                .map(|property| property.definition)
                .collect::<HashSet<_>>();
            let type_definitions = self
                .member_scopes
                .iter()
                .map(|property| property.definition)
                .collect::<HashSet<_>>();
            let visibility_definitions = declaration_visibilities
                .keys()
                .copied()
                .collect::<HashSet<_>>();
            let known_definitions = type_definitions
                .union(&member_definitions)
                .copied()
                .collect::<HashSet<_>>();
            assert!(
                member_definitions.is_subset(&visibility_definitions),
                "Java member definitions require visibility facts: members={member_definitions:?}, visibility={visibility_definitions:?}"
            );
            assert!(
                visibility_definitions.is_subset(&known_definitions),
                "Java visibility facts must name supported type or member definitions: visibility={visibility_definitions:?}, known={known_definitions:?}"
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
                            | DeclaredVisibility::Unknown
                    )),
                "Java declaration visibility must use a Java access level or retain scoped unknown visibility"
            );
        }
        for gap in &self.property_gaps {
            assert!(
                matches!(
                    gap.kind,
                    ResolutionGapKind::ImplicitConstructor
                        | ResolutionGapKind::UnsupportedHierarchyTraversal
                        | ResolutionGapKind::UnsupportedVisibility
                        | ResolutionGapKind::UnexpandedItemMacro
                        | ResolutionGapKind::UnexpandedImplMacro
                ),
                "definition property gap kind is not source-lowerable"
            );
            // "only a synthetic site property gap may omit a typed-frontier
            // row" was asserted here by recomputing the frontier semantic
            // from `(fragment, site)`. A type-frontier semantic is its blob's
            // catalog position now and this validation holds no catalog, so
            // the recomputation is not available to restate it.
            if gap.kind == ResolutionGapKind::UnsupportedVisibility {
                // "visibility gap must remain owned by its exact
                // declaration" was asserted here by recomputing the
                // definition's semantic from `(fragment, site)`. A site does
                // number its own semantic, but only once
                // `ResolutionIdentityCatalogBuilder::finish` has put the
                // catalog in canonical order; this runs inside the lowering,
                // where every id is still a provisional counter. So the
                // recomputation is not available here either, and the gap's
                // ownership is checked by the visibility row it is looked up
                // in below.
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
                assert!(
                    self.language != Language::Java
                        || matches!(
                            visibility,
                            DeclaredVisibility::Protected
                                | DeclaredVisibility::PackagePrivate
                                | DeclaredVisibility::Private
                        ),
                    "only a restricted Java access level can retain unsupported visibility evidence"
                );
                // The reason semantic was compared against a recomputation
                // from `(fragment, site, origin)`, which a catalog position
                // cannot be. Its declaration provenance is asserted above,
                // through the definition, which a site does number.
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
            // Java's scoped Unknown visibility (local and anonymous types)
            // is decided by lexical scope and carries no gap; every other
            // non-public visibility, in any language, carries exactly one.
            let requires_gap = match property.visibility {
                DeclaredVisibility::Public => false,
                DeclaredVisibility::Unknown => self.language != Language::Java,
                _ => true,
            };
            assert_eq!(
                gap_sources.len(),
                usize::from(requires_gap),
                "non-public declaration requires one exact visibility gap provenance, except Java's scoped unknown visibility"
            );
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
            for &result in obligation.extra_result_slots.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, result, "additional call result"),
                    ResolutionTypeSlotRole::CallResult,
                    "additional call result must name a CallResult frontier"
                );
                assert!(
                    projection_outputs.contains(&(obligation.callee_reference, result)),
                    "additional call result requires its binding projection"
                );
            }
            for &argument in obligation.argument_slots.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, argument, "call argument"),
                    ResolutionTypeSlotRole::Argument,
                    "call argument must name an Argument frontier"
                );
            }
            if let Some(segment) = obligation.owner_type_segment {
                assert_eq!(
                    assert_declared_frontier(&inventory, segment, "call type segment"),
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                    "a call's type segment must name its reference's identity frontier"
                );
            }
            for &argument in obligation
                .type_argument_slots
                .iter()
                .chain(obligation.owner_type_argument_slots.iter())
                .chain(obligation.expected_result_slot.iter())
            {
                assert_eq!(
                    assert_declared_frontier(&inventory, argument, "call type argument"),
                    ResolutionTypeSlotRole::DeclaredValue,
                    "call type argument must name the DeclaredValue frontier its type declares"
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
            for result in signature.result_types.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, result.slot, "callable result type"),
                    ResolutionTypeSlotRole::DeclaredValue,
                    "callable result type must name a DeclaredValue frontier"
                );
            }
            for parameter in signature.parameters.iter() {
                assert_eq!(
                    assert_declared_frontier(&inventory, parameter.slot, "callable parameter"),
                    ResolutionTypeSlotRole::DeclaredValue,
                    "callable parameter must name a DeclaredValue frontier"
                );
                // A named parameter's declaration type property names this
                // slot. An unnamed parameter (Rust `_`) binds no definition,
                // so it has no property at all.
                assert!(
                    parameter_declarations
                        .get(&parameter.definition)
                        .is_none_or(|&slot| slot == parameter.slot),
                    "callable parameter's Parameter declaration type property must name its slot"
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
        let mut deferred_definitions = HashSet::default();
        for owner in &self.deferred_member_owners {
            if let Some(frontier) = owner.hierarchy_frontier() {
                assert_eq!(
                    inventory.get(&frontier),
                    Some(&ResolutionTypeSlotRole::TargetTypeIdentity),
                    "a member's declaring contract must retain a type identity"
                );
            }
            assert!(
                inventory.contains_key(&owner.owner_frontier()),
                "deferred member owner must name an exact typed frontier"
            );
            assert!(
                deferred_definitions.insert(owner.definition()),
                "one deferred member owner row per declaration is required"
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

    pub fn type_components(&self) -> &[LoweredTypeComponent] {
        &self.type_components
    }

    pub fn underlying_types(&self) -> &[LoweredUnderlyingType] {
        &self.underlying_types
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

    pub(crate) fn deferred_member_owners(&self) -> &[LoweredDeferredMemberOwner] {
        &self.deferred_member_owners
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
/// One call family's type arguments grouped by call, in position order. Each
/// slot is a DeclaredValue slot at its call, and the positions of one call
/// are contiguous from zero.
fn call_type_arguments_by_call(
    arguments: &[ResolutionCallTypeArgumentFact],
    index: &TypedFactIndex<'_>,
) -> HashMap<ResolutionSiteId, Vec<ResolutionCallTypeArgumentFact>> {
    let mut by_call = HashMap::<_, Vec<_>>::default();
    for argument in arguments {
        let value = index.slot(argument.value);
        assert_eq!(
            value.site, argument.call,
            "a call type argument slot is its call's"
        );
        assert_eq!(value.role, ResolutionTypeSlotRole::DeclaredValue);
        by_call.entry(argument.call).or_default().push(*argument);
    }
    for (call, arguments) in &mut by_call {
        arguments.sort_unstable_by_key(|argument| argument.ordinal);
        for (expected, argument) in arguments.iter().enumerate() {
            assert_eq!(
                usize::try_from(argument.ordinal).expect("u32 ordinal fits usize"),
                expected,
                "call {call} type argument ordinals must be contiguous from zero"
            );
        }
    }
    by_call
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
    let argument_independent_calls = facts
        .engine_rule_eligibilities
        .iter()
        .filter(|eligibility| {
            eligibility.rule == ResolutionEngineRuleKind::ArgumentIndependentBinding
        })
        .map(|eligibility| eligibility.site)
        .collect::<HashSet<_>>();
    let callee_sites = facts
        .calls
        .iter()
        .filter_map(|call| {
            index.identifiers.get(&call.callee).map(|identifier| {
                assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
                call.callee
            })
        })
        .collect::<HashSet<_>>();
    let projected_outputs = facts
        .binding_projections
        .iter()
        .map(|projection| projection.output)
        .collect::<HashSet<_>>();
    let transferred_identity_outputs = facts
        .type_transfers
        .iter()
        .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::TypeIdentity)
        .map(|transfer| transfer.output)
        .collect::<HashSet<_>>();
    let frontiers = facts
        .type_slots
        .iter()
        .map(|slot| {
            let frontier = LoweredTypedFrontier::new(
                identities.semantic(type_slot_semantic_identity(slot.id)),
                slot.role,
            );
            if transferred_identity_outputs.contains(&slot.id)
                && !projected_outputs.contains(&slot.id)
                && index.identifiers.get(&slot.site).is_some_and(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                })
            {
                frontier.with_type_identity_reference(
                    identities.source_reference_semantic(slot.site),
                    identities.source_reference_node(slot.site),
                )
            } else {
                frontier
            }
        })
        .collect::<Vec<_>>();

    let type_components = facts
        .type_components
        .iter()
        .map(|fact| {
            let container = index.slot(fact.container);
            let component = index.slot(fact.component);
            assert_eq!(container.role, ResolutionTypeSlotRole::TargetTypeIdentity);
            assert_eq!(component.role, ResolutionTypeSlotRole::TargetTypeIdentity);
            LoweredTypeComponent::new(
                identities.semantic(type_slot_semantic_identity(fact.container)),
                fact.constructor,
                fact.kind,
                identities.semantic(type_slot_semantic_identity(fact.component)),
            )
        })
        .collect::<Vec<_>>();
    let mut underlying_types = Vec::new();
    for relation in facts
        .declared_type_relations
        .iter()
        .filter(|relation| relation.kind == ResolutionDeclaredTypeRelationKind::UnderlyingType)
    {
        let subject = index.slot(relation.subject);
        let target = relation
            .target
            .expect("an underlying-type relation names its declared type syntax slot");
        let target = index.slot(target);
        assert_eq!(subject.role, ResolutionTypeSlotRole::TargetTypeIdentity);
        assert_eq!(target.role, ResolutionTypeSlotRole::TargetTypeIdentity);
        underlying_types.push(LoweredUnderlyingType::new(
            identities.source_definition_semantic(subject.site),
            identities.semantic(type_slot_semantic_identity(target.id)),
        ));
    }

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
        // A receiver slot can share its source site with the callee. The
        // callee's applicability obligation is not receiver construction
        // evidence. Input-frontier uncertainty still propagates normally.
        let callee_sites = &callee_sites;
        let argument_independent_calls = &argument_independent_calls;
        let completion = completion_for_gaps(
            identities,
            [input.site, output.site].into_iter().flat_map(|site| {
                gaps_by_site
                    .get(&site)
                    .into_iter()
                    .flatten()
                    .filter_map(move |&kind| {
                        (!(kind == ResolutionGapKind::UnsupportedCallApplicability
                            && (callee_sites.contains(&site)
                                || (fact.kind == ResolutionTypeTransferKind::Receiver
                                    && site == output.site
                                    && argument_independent_calls.contains(&site)))))
                        .then_some((site, kind))
                    })
            }),
        );
        transfers.push(LoweredTypeTransfer::new(
            source_slot,
            fact.kind,
            TypeTransferRule::new_with_reference_indirection(
                identities.semantic(transfer_rule_semantic_identity(fact)),
                target_slot,
                i64::from(fact.indirection_delta),
                i64::from(fact.reference_indirection_delta),
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
        let spelling = index.name(fact.name);
        let identity = if fact.kind == IntrinsicTypeKind::Structural {
            identities.semantic(type_slot_semantic_identity(fact.output))
        } else {
            identities.shared_name(super::universe::intrinsic_type_identity_digest(
                language, fact.kind, spelling,
            ))
        };
        let ty = ResolutionTypeRef::new(identity, u32::from(fact.indirection));
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
            spelling,
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
            identities.source_reference_semantic(fact.reference),
            identities.semantic(type_slot_semantic_identity(fact.output)),
            fact.kind,
        ));
    }

    let mut projections_by_reference = HashMap::<_, Vec<_>>::default();
    for projection in &facts.binding_projections {
        projections_by_reference
            .entry(projection.reference)
            .or_default()
            .push(projection);
    }
    // Call-binding rules ride on the call obligation; the open-member-surface
    // rule names a reference that need not be a call at all -- `Host::ITEM` is
    // a constant read -- and rides on that reference's qualified route rows
    // instead. Splitting them here is what lets one producer fact carry both.
    let mut eligible_rules_by_call = HashMap::<_, Vec<_>>::default();
    let mut open_member_surfaces = HashSet::default();
    for eligibility in &facts.engine_rule_eligibilities {
        if eligibility.rule == ResolutionEngineRuleKind::OpenMemberSurface {
            open_member_surfaces.insert(eligibility.site);
            continue;
        }
        eligible_rules_by_call
            .entry(eligibility.site)
            .or_default()
            .push(eligibility.rule);
    }

    let go_root_type_or_value_sites = if language == Language::Go {
        facts
            .root_references
            .iter()
            .filter_map(|reference| {
                index
                    .identifiers
                    .get(&reference.reference)
                    .filter(|identifier| identifier.namespace == ResolutionNamespace::TypeOrValue)
                    .map(|_| reference.reference)
            })
            .collect::<HashSet<_>>()
    } else {
        HashSet::default()
    };
    let mut qualified_routes = Vec::new();
    for identifier in index.identifiers.values() {
        if go_root_type_or_value_sites.contains(&identifier.site) {
            // An ambiguous Go package-qualified terminal is resolved by its
            // root route. Its receiver slot names the package qualifier, not
            // a runtime or type value for the ordinary member evaluator.
            continue;
        }
        let Some(qualifier) = identifier.qualifier else {
            continue;
        };
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        let Some(projections) = projections_by_reference.get(&identifier.site) else {
            // Without a projection output this layer cannot own the typed
            // obligation. The lexical QualifiedReference gap remains live.
            continue;
        };
        for projection in projections {
            let reference = identities.source_reference_semantic(identifier.site);
            let coarse_gap_reason = identities.semantic(gap_reason_semantic_identity(
                identifier.site,
                LoweringGapOrigin::QualifiedReference,
            ));
            let route_namespace =
                if projection.kind == BindingProjectionKind::TargetCallableResultType {
                    ResolutionNamespace::Callable
                } else {
                    identifier.namespace
                };
            // Rust associated functions inhabit the value namespace even when
            // used without a call. Keep the ordinary value route for constants
            // and constructors; a callable alternative admits method items.
            let member_routes = if language == Language::Rust
                && route_namespace == ResolutionNamespace::Value
                && projection.kind == BindingProjectionKind::TargetDeclaredValueType
            {
                RUST_VALUE_MEMBER_ROUTES
            } else {
                lookup_routes(route_namespace)
            };
            for &(precedence_ordinal, namespace) in member_routes {
                let source_namespace = if identifier.namespace == ResolutionNamespace::TypeOrValue {
                    namespace
                } else {
                    identifier.namespace
                };
                qualified_routes.push(LoweredQualifiedSeededRoute::new_with_source_lookup(
                    reference,
                    identities.semantic(type_slot_semantic_identity(qualifier)),
                    identities.lookup_semantic(language, namespace, index.name(identifier.name)),
                    namespace,
                    identities.lookup_semantic(
                        language,
                        source_namespace,
                        index.name(identifier.name),
                    ),
                    precedence_ordinal,
                    identities.semantic(type_slot_semantic_identity(projection.output)),
                    projection.kind,
                    coarse_gap_reason,
                    open_member_surfaces.contains(&identifier.site),
                ));
            }
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
            identities.source_definition_semantic(fact.declaration),
            identities.semantic(type_slot_semantic_identity(fact.slot)),
            fact.role,
        ));
    }

    let member_scopes = lower_member_scope_properties(identities, &index);
    let deferred_member_owners =
        lower_deferred_member_owner_properties(identities, language, facts, &index);
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
    let mut type_arguments_by_call =
        call_type_arguments_by_call(&facts.call_type_arguments, &index);
    let mut owner_type_arguments_by_call =
        call_type_arguments_by_call(&facts.call_owner_type_arguments, &index);
    let mut owner_type_segments_by_call = HashMap::default();
    for segment in &facts.call_owner_type_segments {
        assert_eq!(
            index.slot(segment.identity).role,
            ResolutionTypeSlotRole::TargetTypeIdentity
        );
        assert!(
            owner_type_segments_by_call
                .insert(segment.call, segment.identity)
                .is_none(),
            "one call has one type segment: {segment:?}"
        );
    }
    let mut expected_results_by_call = HashMap::default();
    for expected in &facts.call_expected_results {
        let value = index.slot(expected.value);
        assert_eq!(
            value.site, expected.call,
            "an expected result slot is its call's"
        );
        assert_eq!(value.role, ResolutionTypeSlotRole::DeclaredValue);
        assert!(
            expected_results_by_call
                .insert(expected.call, expected.value)
                .is_none(),
            "one call has one expected result: {expected:?}"
        );
    }
    for rules in eligible_rules_by_call.values_mut() {
        rules.sort_unstable();
        assert!(rules.windows(2).all(|pair| pair[0] != pair[1]));
    }
    let mut call_obligations = Vec::with_capacity(facts.calls.len());
    for call in &facts.calls {
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
        let mut slots_of = |arguments: Option<Vec<ResolutionCallTypeArgumentFact>>| {
            arguments
                .unwrap_or_default()
                .into_iter()
                .map(|argument| identities.semantic(type_slot_semantic_identity(argument.value)))
                .collect::<Vec<_>>()
        };
        let owner_type_argument_slots = slots_of(owner_type_arguments_by_call.remove(&call.call));
        let type_argument_slots = slots_of(type_arguments_by_call.remove(&call.call));
        let owner_type_segment = owner_type_segments_by_call
            .remove(&call.call)
            .map(|slot| identities.semantic(type_slot_semantic_identity(slot)));
        let expected_result_slot = expected_results_by_call
            .remove(&call.call)
            .map(|slot| identities.semantic(type_slot_semantic_identity(slot)));
        let extra_result_slots = call
            .extra_result_slots
            .iter()
            .map(|&slot| identities.semantic(type_slot_semantic_identity(slot)))
            .collect::<Vec<_>>();
        call_obligations.push(
            LoweredCallApplicabilityObligation::new(
                call_semantic,
                identities.source_reference_semantic(call.callee),
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
            )
            .with_extra_result_slots(extra_result_slots)
            .with_type_argument_slots(type_argument_slots)
            .with_owner_type_arguments(owner_type_segment, owner_type_argument_slots)
            .with_expected_result_slot(expected_result_slot),
        );
    }
    assert!(
        type_arguments_by_call.is_empty()
            && owner_type_arguments_by_call.is_empty()
            && owner_type_segments_by_call.is_empty()
            && expected_results_by_call.is_empty(),
        "every call type argument names an emitted call: {type_arguments_by_call:?} \
         {owner_type_arguments_by_call:?} {owner_type_segments_by_call:?} \
         {expected_results_by_call:?}"
    );
    assert!(
        eligible_rules_by_call.is_empty(),
        "engine rule eligibility must name an emitted call obligation: {eligible_rules_by_call:?}"
    );

    let parameters_by_callable = normalized_callable_parameters(facts, &index);
    let mut result_bindings_by_callable = HashMap::<_, Vec<_>>::default();
    for binding in &facts.callable_result_bindings {
        let parameters = parameters_by_callable
            .get(&binding.callable)
            .unwrap_or_else(|| {
                panic!("result binding names a callable with no parameters: {binding:?}")
            });
        assert!(
            parameters
                .iter()
                .any(|parameter| parameter.ordinal == binding.parameter_ordinal),
            "result binding names one of its callable's parameters: {binding:?}"
        );
        result_bindings_by_callable
            .entry(binding.callable)
            .or_default()
            .push(LoweredCallableResultBinding::new(
                binding.parameter_ordinal,
                i64::from(binding.indirection_delta),
                i64::from(binding.reference_indirection_delta),
            ));
    }
    let mut receivers_by_callable = HashMap::default();
    for receiver in &facts.callable_receivers {
        assert!(
            receivers_by_callable
                .insert(receiver.callable, receiver.form)
                .is_none(),
            "one callable declares one receiver: {receiver:?}"
        );
    }
    let result_type_parameters = |facts: &[ResolutionCallableResultTypeParameterFact]| {
        let mut by_callable = HashMap::default();
        for parameter in facts {
            assert!(
                by_callable
                    .insert(
                        parameter.callable,
                        LoweredCallableResultBinding::new(
                            parameter.position,
                            i64::from(parameter.indirection_delta),
                            i64::from(parameter.reference_indirection_delta),
                        ),
                    )
                    .is_none(),
                "one callable declares one result type: {parameter:?}"
            );
        }
        by_callable
    };
    let mut result_type_parameters_by_callable =
        result_type_parameters(&facts.callable_result_type_parameters);
    let mut result_owner_type_parameters_by_callable =
        result_type_parameters(&facts.callable_result_owner_type_parameters);
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
                    identities.source_definition_semantic(parameter.parameter),
                    identities.semantic(type_slot_semantic_identity(parameter.value_type)),
                    parameter.repeated,
                )
            })
            .collect::<Vec<_>>();
        let lowered_result_types = header
            .result_types
            .iter()
            .map(|result| {
                let value_type = index.slot(result.value_type);
                assert_eq!(
                    value_type.site, callable,
                    "callable result type slots belong to their signature declaration"
                );
                assert_eq!(value_type.role, ResolutionTypeSlotRole::DeclaredValue);
                LoweredCallableResultTypeProperty::new(
                    result.ordinal,
                    identities.semantic(type_slot_semantic_identity(result.value_type)),
                )
            })
            .collect::<Vec<_>>();
        let completion = completion_for_site_iter(
            identities,
            &gaps_by_site,
            std::iter::once(callable).chain(parameters.iter().map(|row| row.parameter)),
        );
        callable_signatures.push(
            LoweredCallableSignatureProperty::new(
                identities.source_definition_semantic(callable),
                header.type_parameter_count,
                lowered_parameters,
                completion,
            )
            .with_result_types(lowered_result_types)
            .with_result_bindings(
                result_bindings_by_callable
                    .remove(&callable)
                    .unwrap_or_default(),
            )
            .with_receiver(receivers_by_callable.remove(&callable))
            .with_result_type_parameter(result_type_parameters_by_callable.remove(&callable))
            .with_result_owner_type_parameter(
                result_owner_type_parameters_by_callable.remove(&callable),
            ),
        );
    }
    assert!(
        result_type_parameters_by_callable.is_empty()
            && result_owner_type_parameters_by_callable.is_empty(),
        "every result type parameter names a callable with a signature header: \
         {result_type_parameters_by_callable:?} {result_owner_type_parameters_by_callable:?}"
    );
    assert!(
        receivers_by_callable.is_empty(),
        "every receiver form names a callable with a signature header: {receivers_by_callable:?}"
    );
    assert!(
        result_bindings_by_callable.is_empty(),
        "every result binding names a callable with a signature header: {result_bindings_by_callable:?}"
    );

    LoweredTypedFragment::new_with_type_relations(
        fragment,
        language,
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
    )
}

fn lower_deferred_member_owner_properties(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
    index: &TypedFactIndex<'_>,
) -> Vec<LoweredDeferredMemberOwner> {
    let hierarchy_by_member = super::common_fact_lowering::member_hierarchy_frontiers(facts);
    let mut seen = HashSet::default();
    let mut properties = Vec::with_capacity(facts.deferred_member_owners.len());
    for &fact in &facts.deferred_member_owners {
        assert!(
            seen.insert(fact),
            "duplicate deferred member-owner property: {fact:?}"
        );
        let owner_slot = index.slot(fact.owner_type);
        assert_eq!(
            owner_slot.role,
            ResolutionTypeSlotRole::TargetTypeIdentity,
            "deferred member owner must resolve through a target type identity: {fact:?}"
        );
        let member = index.definition_identifier(fact.member);
        let lookup = identities.lookup_semantic(
            language,
            member_lookup_namespace(fact.kind),
            index.name(member.name),
        );
        properties.push(
            LoweredDeferredMemberOwner::new(
                identities.source_definition_semantic(fact.member),
                identities.semantic(type_slot_semantic_identity(fact.owner_type)),
                lookup,
                fact.kind,
                fact.access,
                fact.qualifier_compatibility,
            )
            .with_hierarchy_frontier(
                hierarchy_by_member
                    .get(&fact.member)
                    .map(|&slot| identities.semantic(type_slot_semantic_identity(slot))),
            ),
        );
    }
    properties.sort_unstable_by_key(|property| {
        (
            property.owner_frontier(),
            property.lookup(),
            property.definition(),
            property.kind(),
            property.access(),
            property.qualifier_compatibility(),
        )
    });
    properties
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
                identities.source_definition_semantic(declaration),
                identities.source_scope_node(scope),
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
            identities.source_definition_semantic(fact.declaration),
            fact.visibility,
        ));
    }

    if language == Language::Java {
        let member_definitions = facts
            .member_owners
            .iter()
            .map(|owner| owner.member)
            .collect::<HashSet<_>>();
        assert!(
            member_definitions.is_subset(&eligible),
            "Java member definitions must be visibility-eligible: members={member_definitions:?}, eligible={eligible:?}"
        );
        assert_eq!(
            seen, eligible,
            "Java visibility inventory must cover every eligible declaration exactly once"
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
            let requires_gap = !matches!(
                fact.visibility,
                DeclaredVisibility::Public | DeclaredVisibility::Unknown
            );
            assert_eq!(
                gap_count,
                usize::from(requires_gap),
                "restricted Java access levels require one visibility gap; scoped unknown visibility does not: {fact:?}"
            );
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
        let owner_definition = identities.source_definition_semantic(fact.owner);
        let owner_scope_head = *member_scope_by_definition
            .get(&owner_definition)
            .unwrap_or_else(|| panic!("member owner {} has no type-body scope", fact.owner));
        member_owners.push(LoweredMemberOwnerProperty::new(
            identities.source_definition_semantic(fact.member),
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
            identities.source_definition_semantic(fact.constructed_type),
            identities.source_definition_semantic(fact.required_owner),
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
            identities.source_definition_semantic(fact.subtype),
            identities.source_reference_semantic(fact.supertype_reference),
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
    let deferred_member_sites = facts
        .deferred_member_owners
        .iter()
        .map(|owner| owner.member)
        .collect::<HashSet<_>>();
    let mut property_gaps = Vec::new();
    for gap in &facts.gaps {
        if matches!(
            gap.kind,
            ResolutionGapKind::UnexpandedItemMacro | ResolutionGapKind::UnexpandedImplMacro
        ) {
            // The expansion can add impls to every type its scope declares,
            // so each of them carries the invocation's reason as a
            // member-surface property. The property is positioned on the
            // type's own declaration, which keeps one owner per source
            // provenance while one invocation reaches several types.
            let scope = index.site(gap.site).scope;
            let reason_semantic = identities.semantic(gap_reason_semantic_identity(
                gap.site,
                LoweringGapOrigin::Extracted(gap.kind),
            ));
            for site in &facts.sites {
                if site.kind != ResolutionSiteKind::TypeDeclaration || site.scope != scope {
                    continue;
                }
                validate_type_definition(site.id, index);
                for frontier in index.type_frontiers(identities, site.id) {
                    property_gaps.push(LoweredDefinitionPropertyGap::new(
                        identities.source_definition_semantic(site.id),
                        site.id,
                        gap.kind,
                        frontier,
                        reason_semantic,
                    ));
                }
            }
            continue;
        }
        let owner = match gap.kind {
            ResolutionGapKind::ImplicitConstructor => {
                validate_type_definition(gap.site, index);
                Some(gap.site)
            }
            ResolutionGapKind::UnsupportedHierarchyTraversal => {
                hierarchy_gap_owner(gap.site, index, facts)
            }
            ResolutionGapKind::UnsupportedVisibility => {
                if index.site(gap.site).kind == ResolutionSiteKind::TypeDeclaration {
                    validate_type_definition(gap.site, index);
                } else if deferred_member_sites.contains(&gap.site) {
                    index.definition_identifier(gap.site);
                    // An inherent impl's method, associated constant or
                    // associated type carries its own visibility.
                    assert!(
                        matches!(
                            index.site(gap.site).kind,
                            ResolutionSiteKind::CallableDeclaration
                                | ResolutionSiteKind::ValueDeclaration
                                | ResolutionSiteKind::TypeAliasDeclaration
                        ),
                        "deferred visibility gap must name an associated item: {:?}",
                        index.site(gap.site)
                    );
                } else if let Some(&owner) = source_member_owner.get(&gap.site) {
                    validate_member_owner(owner, index);
                } else {
                    // Module and lexical declarations also carry access
                    // obligations. Their exact definition and positive,
                    // producer-eligible visibility row are the owner proof.
                    index.definition_identifier(gap.site);
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
                identities.source_definition_semantic(owner),
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
            assert!(
                matches!(
                    owner_site.kind,
                    ResolutionSiteKind::TypeDeclaration
                        | ResolutionSiteKind::ConstructorDeclaration
                ),
                "type-body scope owner must be a type or constructor declaration"
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
            for &extra_result in &call.extra_result_slots {
                let extra_result = self.slot(extra_result);
                assert_eq!(extra_result.site, call.call);
                assert_eq!(extra_result.role, ResolutionTypeSlotRole::CallResult);
            }
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
        let mut expected_signature_headers = callable_definitions;
        for header in &facts.callable_signatures {
            let callable = self.site(header.callable);
            if callable.kind == ResolutionSiteKind::ValueDeclaration {
                assert!(
                    !header.result_types.is_empty(),
                    "a value signature carries a function result type: {header:?}"
                );
                expected_signature_headers.insert(header.callable);
            } else {
                assert!(matches!(
                    callable.kind,
                    ResolutionSiteKind::CallableDeclaration
                        | ResolutionSiteKind::ConstructorDeclaration
                ));
            }
            self.definition_identifier(header.callable);
            for result in &header.result_types {
                let value_type = self.slot(result.value_type);
                assert_eq!(value_type.site, header.callable);
                assert_eq!(value_type.role, ResolutionTypeSlotRole::DeclaredValue);
            }
            assert!(
                signature_headers.insert(header.callable),
                "duplicate callable signature header: {header:?}"
            );
        }
        assert_eq!(
            signature_headers, expected_signature_headers,
            "every callable definition and typed function value requires exactly one signature header"
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
            // A wildcard parameter (Rust `_`) binds nothing, so its site has
            // no identifier and its slot no declaration-type property: there
            // is no definition to carry one. A named parameter has both.
            let named = self
                .identifiers
                .get(&parameter.parameter)
                .map(|identifier| {
                    assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
                });
            let value_type = self.slot(parameter.value_type);
            assert_eq!(value_type.site, parameter.parameter);
            assert_eq!(value_type.role, ResolutionTypeSlotRole::DeclaredValue);
            assert_eq!(
                facts.declaration_type_slots.iter().any(|property| {
                    property.declaration == parameter.parameter
                        && property.slot == parameter.value_type
                        && property.role == DeclarationTypeRole::Parameter
                }),
                named.is_some(),
                "a named callable parameter carries its declared type property and a \
                 wildcard carries none: {parameter:?}"
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
            validate_member_scope_owner(owner, self);
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
    UnaryIndirection,
    Transfer,
    TypeUnion,
    Intrinsic,
    Projection,
}

/// A unary star has exactly two disjoint category alternatives over one input.
/// Validate the pair before treating it as one output producer.
fn validate_indirection_producers<Slot: Copy + Eq + std::hash::Hash + std::fmt::Debug>(
    rows: impl Iterator<Item = (Slot, Slot, i64, i64, TypeTransferValueTransform)>,
) {
    let mut groups = HashMap::default();
    for (source, target, delta, reference_delta, transform) in rows {
        assert_eq!(
            reference_delta, 0,
            "unary pointers do not change reference layers"
        );
        let bit = match (delta, transform) {
            (1, TypeTransferValueTransform::TypeObjectOnly) => 1,
            (-1, TypeTransferValueTransform::AddressableRuntimeOnly) => 2,
            other => panic!("invalid unary indirection transfer {other:?}"),
        };
        let (previous_source, mask) = groups.entry(target).or_insert((source, 0));
        assert_eq!(
            *previous_source, source,
            "unary alternatives must share an operand"
        );
        assert_eq!(*mask & bit, 0, "unary alternative repeated for {target:?}");
        *mask |= bit;
    }
    for (target, (_, mask)) in groups {
        assert_eq!(
            mask, 3,
            "unary indirection needs both category alternatives for {target:?}"
        );
    }
}

/// A typed slot has one affirmative producer. TypeUnion combines declared
/// inputs; UnaryIndirection combines its validated disjoint category pair.
/// Every other producer remains exclusive, including same-family duplicates.
fn validate_output_producers(facts: &FileResolutionFacts, index: &TypedFactIndex<'_>) {
    validate_indirection_producers(
        facts
            .type_transfers
            .iter()
            .filter(|fact| fact.kind == ResolutionTypeTransferKind::UnaryIndirection)
            .map(|fact| {
                (
                    fact.input,
                    fact.output,
                    i64::from(fact.indirection_delta),
                    i64::from(fact.reference_indirection_delta),
                    lower_value_transform(fact.value_transform),
                )
            }),
    );
    let mut producers = HashMap::default();
    let mut register = |slot: ResolutionTypeSlotId, family: TypedOutputProducerFamily| {
        index.slot(slot);
        if let Some(previous) = producers.insert(slot, family)
            && (previous != family
                || !matches!(
                    family,
                    TypedOutputProducerFamily::TypeUnion
                        | TypedOutputProducerFamily::UnaryIndirection
                ))
        {
            panic!("typed slot {slot} has multiple output producers: {previous:?} and {family:?}");
        }
    };
    for transfer in &facts.type_transfers {
        register(
            transfer.output,
            match transfer.kind {
                ResolutionTypeTransferKind::TypeUnion => TypedOutputProducerFamily::TypeUnion,
                ResolutionTypeTransferKind::UnaryIndirection => {
                    TypedOutputProducerFamily::UnaryIndirection
                }
                _ => TypedOutputProducerFamily::Transfer,
            },
        );
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
    assert!(
        transfer_accepts_output_role(fact.kind, output),
        "type-transfer kind and output role disagree: {fact:?}"
    );
    match fact.kind {
        ResolutionTypeTransferKind::TypeIdentity
        | ResolutionTypeTransferKind::TypeUnion
        | ResolutionTypeTransferKind::TypeAlias => {
            assert_eq!(
                input,
                ResolutionTypeSlotRole::TargetTypeIdentity,
                "type-identity input must retain a type object: {fact:?}"
            )
        }
        ResolutionTypeTransferKind::DeclaredType => assert_eq!(
            input,
            ResolutionTypeSlotRole::TargetTypeIdentity,
            "declared-type transfer input must retain a type object: {fact:?}"
        ),
        // A `let` initializer is a direct call or a plain runtime identifier;
        // the first publishes a call result and the second the referenced
        // binding's expression value. Nothing else produces a typed slot a
        // binding can be initialized from.
        ResolutionTypeTransferKind::Initialization => assert!(
            matches!(
                input,
                ResolutionTypeSlotRole::CallResult | ResolutionTypeSlotRole::ExpressionValue
            ),
            "initialization transfer input must retain the initializer's produced value: {fact:?}"
        ),
        ResolutionTypeTransferKind::Unwrap => assert!(
            matches!(
                input,
                ResolutionTypeSlotRole::CallResult | ResolutionTypeSlotRole::ExpressionValue
            ),
            "unwrap transfer input must retain the unwrapped operand's value: {fact:?}"
        ),
        ResolutionTypeTransferKind::ComponentElement
        | ResolutionTypeTransferKind::ComponentKey
        | ResolutionTypeTransferKind::ComponentValue => assert!(
            matches!(
                input,
                ResolutionTypeSlotRole::TargetTypeIdentity
                    | ResolutionTypeSlotRole::DeclaredValue
                    | ResolutionTypeSlotRole::ExpressionValue
                    | ResolutionTypeSlotRole::CallResult
            ),
            "component transfer input must retain a resolved type or value: {fact:?}"
        ),
        ResolutionTypeTransferKind::Assignment
        | ResolutionTypeTransferKind::Construction
        | ResolutionTypeTransferKind::Receiver
        | ResolutionTypeTransferKind::Argument
        | ResolutionTypeTransferKind::Return
        | ResolutionTypeTransferKind::UnaryIndirection
        | ResolutionTypeTransferKind::AddressOf => {}
    }
    if fact.kind == ResolutionTypeTransferKind::AddressOf {
        validate_address_of_transfer(
            i64::from(fact.indirection_delta),
            i64::from(fact.reference_indirection_delta),
            lower_value_transform(fact.value_transform),
        );
        assert!(
            matches!(
                input,
                ResolutionTypeSlotRole::ExpressionValue | ResolutionTypeSlotRole::CallResult
            ),
            "address-of requires an expression operand"
        );
    }
    if matches!(
        fact.kind,
        ResolutionTypeTransferKind::TypeIdentity | ResolutionTypeTransferKind::TypeUnion
    ) {
        assert_eq!(
            (fact.indirection_delta, fact.reference_indirection_delta),
            (0, 0),
            "type-identity transfer must preserve indirection: {fact:?}"
        );
        assert_eq!(
            fact.value_transform,
            ResolutionTypeTransferValueTransform::Preserve,
            "type-identity transfer must preserve its type-object category: {fact:?}"
        );
    }
    if fact.kind == ResolutionTypeTransferKind::TypeAlias {
        assert!(fact.indirection_delta >= 0);
        assert!((0..=fact.indirection_delta).contains(&fact.reference_indirection_delta));
        assert_eq!(
            fact.value_transform,
            ResolutionTypeTransferValueTransform::Preserve
        );
    }
    if fact.kind == ResolutionTypeTransferKind::Initialization {
        assert_eq!(
            (fact.indirection_delta, fact.reference_indirection_delta),
            (0, 0),
            "initialization transfer must preserve indirection: {fact:?}"
        );
        assert!(
            matches!(
                fact.value_transform,
                ResolutionTypeTransferValueTransform::Preserve
                    | ResolutionTypeTransferValueTransform::AddressableRuntimeOnly
            ),
            "initialization must preserve runtime category or admit an addressable runtime value: {fact:?}"
        );
    }
    if fact.kind == ResolutionTypeTransferKind::Unwrap {
        // An unwrap discharges exactly the one unproven layer that the
        // `Option`/`Result` payload encoding adds, and adds no reference
        // layer, so the output still satisfies references <= total.
        assert_eq!(
            (fact.indirection_delta, fact.reference_indirection_delta),
            (-1, 0),
            "unwrap transfer must remove exactly one unproven indirection layer: {fact:?}"
        );
        assert_eq!(
            fact.value_transform,
            ResolutionTypeTransferValueTransform::Preserve,
            "unwrap transfer must preserve its runtime value category: {fact:?}"
        );
    }
}

fn validate_address_of_transfer(
    delta: i64,
    reference_delta: i64,
    transform: TypeTransferValueTransform,
) {
    assert_eq!(
        (delta, reference_delta),
        (1, 0),
        "address-of adds one pointer layer"
    );
    assert!(
        matches!(
            transform,
            TypeTransferValueTransform::AddressableOperandOnly
                | TypeTransferValueTransform::RuntimeOnly
        ),
        "address-of must filter its runtime operand and produce a non-addressable value"
    );
}

fn transfer_accepts_output_role(
    kind: ResolutionTypeTransferKind,
    output: ResolutionTypeSlotRole,
) -> bool {
    let expected = match kind {
        ResolutionTypeTransferKind::TypeIdentity
        | ResolutionTypeTransferKind::TypeUnion
        | ResolutionTypeTransferKind::TypeAlias => ResolutionTypeSlotRole::TargetTypeIdentity,
        ResolutionTypeTransferKind::DeclaredType => ResolutionTypeSlotRole::DeclaredValue,
        ResolutionTypeTransferKind::Initialization => ResolutionTypeSlotRole::DeclaredValue,
        ResolutionTypeTransferKind::ComponentElement
        | ResolutionTypeTransferKind::ComponentKey
        | ResolutionTypeTransferKind::ComponentValue => {
            return matches!(
                output,
                ResolutionTypeSlotRole::DeclaredValue | ResolutionTypeSlotRole::TargetTypeIdentity
            );
        }
        ResolutionTypeTransferKind::Unwrap => ResolutionTypeSlotRole::CallResult,
        ResolutionTypeTransferKind::Assignment => ResolutionTypeSlotRole::AssignmentValue,
        ResolutionTypeTransferKind::Construction => {
            return matches!(
                output,
                ResolutionTypeSlotRole::CallResult | ResolutionTypeSlotRole::ExpressionValue
            );
        }
        ResolutionTypeTransferKind::Receiver => ResolutionTypeSlotRole::Receiver,
        ResolutionTypeTransferKind::Argument => ResolutionTypeSlotRole::Argument,
        ResolutionTypeTransferKind::Return => ResolutionTypeSlotRole::ReturnValue,
        ResolutionTypeTransferKind::UnaryIndirection | ResolutionTypeTransferKind::AddressOf => {
            ResolutionTypeSlotRole::ExpressionValue
        }
    };
    output == expected
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
        ResolutionTypeTransferValueTransform::TypeObjectOnly => {
            TypeTransferValueTransform::TypeObjectOnly
        }
        ResolutionTypeTransferValueTransform::AddressableRuntimeOnly => {
            TypeTransferValueTransform::AddressableRuntimeOnly
        }
        ResolutionTypeTransferValueTransform::AddressableOperandOnly => {
            TypeTransferValueTransform::AddressableOperandOnly
        }
        ResolutionTypeTransferValueTransform::RuntimeOnly => {
            TypeTransferValueTransform::RuntimeOnly
        }
    }
}

fn validate_projection(
    fact: BindingProjectionFact,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) {
    let reference = index.reference_identifier(fact.reference);
    let reference_site = index.site(fact.reference);
    let output = index.slot(fact.output);
    let (namespace, role) = projection_contract(fact.kind);
    let callable_value_reference = fact.kind == BindingProjectionKind::TargetCallableResultType
        && reference.namespace == ResolutionNamespace::Value
        && matches!(
            reference_site.kind,
            ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
        );
    let callable_type_or_value_reference = fact.kind
        == BindingProjectionKind::TargetCallableResultType
        && reference.namespace == ResolutionNamespace::TypeOrValue
        && reference_site.kind == ResolutionSiteKind::CallableReference;
    assert!(
        reference.namespace == namespace
            || callable_value_reference
            || callable_type_or_value_reference,
        "binding projection namespace does not match its contract: {fact:?}"
    );
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
            facts.calls.iter().any(|call| {
                call.callee == fact.reference
                    && (call.result == fact.output
                        || call.extra_result_slots.contains(&fact.output))
            }),
            "call-result projection is not attached to its call: {fact:?}"
        );
    }
}

const fn projection_contract(
    kind: BindingProjectionKind,
) -> (ResolutionNamespace, ResolutionTypeSlotRole) {
    match kind {
        BindingProjectionKind::TargetTypeIdentity
        | BindingProjectionKind::TargetNominalTypeIdentity => (
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
        BindingProjectionKind::TargetMemberOwnerType => (
            ResolutionNamespace::Type,
            ResolutionTypeSlotRole::TargetTypeIdentity,
        ),
    }
}

fn validate_declaration_type(fact: DeclarationTypeSlotFact, index: &TypedFactIndex<'_>) {
    let declaration = index.site(fact.declaration);
    index.definition_identifier(fact.declaration);
    let slot = index.slot(fact.slot);
    assert_eq!(slot.site, fact.declaration);
    assert_eq!(
        slot.role,
        match fact.role {
            DeclarationTypeRole::Identity | DeclarationTypeRole::NominalIdentity =>
                ResolutionTypeSlotRole::TargetTypeIdentity,
            _ => ResolutionTypeSlotRole::DeclaredValue,
        }
    );
    match fact.role {
        DeclarationTypeRole::Identity | DeclarationTypeRole::NominalIdentity => {
            assert!(matches!(
                declaration.kind,
                ResolutionSiteKind::TypeAliasDeclaration | ResolutionSiteKind::TypeDeclaration
            ));
        }
        DeclarationTypeRole::Value | DeclarationTypeRole::Parameter => {
            assert_eq!(declaration.kind, ResolutionSiteKind::ValueDeclaration);
        }
        DeclarationTypeRole::Return => {
            assert_eq!(declaration.kind, ResolutionSiteKind::CallableDeclaration);
        }
    }
}

fn validate_member_owner(fact: ResolutionMemberOwnerFact, index: &TypedFactIndex<'_>) {
    validate_member_scope_owner(fact.owner, index);
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

fn validate_member_scope_owner(site: ResolutionSiteId, index: &TypedFactIndex<'_>) {
    if index.site(site).kind == ResolutionSiteKind::ConstructorDeclaration {
        assert_eq!(
            index.definition_identifier(site).namespace,
            ResolutionNamespace::Constructor
        );
    } else {
        validate_type_definition(site, index);
    }
}

fn validate_type_definition(site: ResolutionSiteId, index: &TypedFactIndex<'_>) {
    assert_eq!(index.site(site).kind, ResolutionSiteKind::TypeDeclaration);
    assert_eq!(
        index.definition_identifier(site).namespace,
        ResolutionNamespace::Type
    );
}

/// The definition a hierarchy gap is a property of: the type declaration
/// itself, or the subtype whose supertype property names this reference.
///
/// A hierarchy gap can also sit on a frontier that no definition owns -- a
/// trait's abstract `Self`, or the `dyn`, `impl Trait` and bounded head of a
/// declared type. Those carry their incompleteness through the frontier's own
/// completion reasons, which `gaps_by_site` already supplies, and produce no
/// definition property row. Any other site kind is a producer error.
fn hierarchy_gap_owner(
    site: ResolutionSiteId,
    index: &TypedFactIndex<'_>,
    facts: &FileResolutionFacts,
) -> Option<ResolutionSiteId> {
    if index.site(site).kind == ResolutionSiteKind::TypeDeclaration {
        validate_type_definition(site, index);
        return Some(site);
    }
    let mut owners = facts
        .supertypes
        .iter()
        .filter(|supertype| supertype.supertype_reference == site)
        .map(|supertype| supertype.subtype);
    let Some(owner) = owners.next() else {
        assert!(
            matches!(
                index.site(site).kind,
                ResolutionSiteKind::TypeReference
                    | ResolutionSiteKind::SyntheticReference
                    | ResolutionSiteKind::UnsupportedExpression
            ),
            "hierarchy gap at {site} must name a type declaration, a supertype reference, a type reference, a synthetic reference or an unsupported expression"
        );
        return None;
    };
    assert!(
        owners.next().is_none(),
        "hierarchy gap at {site} has multiple owning subtype properties"
    );
    validate_type_definition(owner, index);
    Some(owner)
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
    completion_for_gaps(
        identities,
        sites.into_iter().flat_map(|site| {
            gaps_by_site
                .get(&site)
                .into_iter()
                .flatten()
                .map(move |&kind| (site, kind))
        }),
    )
}

fn completion_for_gaps(
    identities: &mut ResolutionIdentityCatalogBuilder,
    gaps: impl IntoIterator<Item = (ResolutionSiteId, ResolutionGapKind)>,
) -> ResolutionCompletion {
    let mut reasons = Vec::new();
    for (site, kind) in gaps {
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

const RUST_VALUE_MEMBER_ROUTES: &[(u32, ResolutionNamespace)] = &[
    (0, ResolutionNamespace::Value),
    (1, ResolutionNamespace::Callable),
];

fn assert_source_lowerable_qualified_routes(routes: &[LoweredQualifiedSeededRoute]) {
    let mut routes_by_projection: HashMap<_, Vec<_>> = HashMap::default();
    for route in routes {
        assert!(
            route.projection_kind == BindingProjectionKind::TargetCallableResultType
                || route.requires_type_qualifier()
                || route.source_lookup == route.lookup,
            "only callable result or method-value projections may separate source and member lookup"
        );
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
        let expected_shape = if projection_routes
            .iter()
            .any(|route| route.requires_type_qualifier())
        {
            RUST_VALUE_MEMBER_ROUTES
        } else {
            lookup_routes(projection_contract(kind).0)
        };
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
    validate_indirection_producers(
        transfers
            .iter()
            .filter(|row| row.kind == ResolutionTypeTransferKind::UnaryIndirection)
            .map(|row| {
                (
                    row.source_slot(),
                    row.rule.target_slot(),
                    row.rule.indirection_delta(),
                    row.rule.reference_indirection_delta(),
                    row.rule.value_transform(),
                )
            }),
    );
    let mut producers = HashMap::default();
    let mut register = |slot: SemanticId, family: TypedOutputProducerFamily| {
        if let Some(previous) = producers.insert(slot, family)
            && (previous != family
                || !matches!(
                    family,
                    TypedOutputProducerFamily::TypeUnion
                        | TypedOutputProducerFamily::UnaryIndirection
                ))
        {
            panic!(
                "typed frontier {slot:?} has multiple output producers: {previous:?} and {family:?}"
            );
        }
    };
    for transfer in transfers {
        register(
            transfer.rule.target_slot(),
            match transfer.kind {
                ResolutionTypeTransferKind::TypeUnion => TypedOutputProducerFamily::TypeUnion,
                ResolutionTypeTransferKind::UnaryIndirection => {
                    TypedOutputProducerFamily::UnaryIndirection
                }
                _ => TypedOutputProducerFamily::Transfer,
            },
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
            projection_references.insert((projection.reference, projection.output_slot)),
            "one binding projection per (reference, output slot) is required"
        );
    }
    let mut qualified_route_ordinals = HashSet::default();
    let mut coarse_gap_reason_owners = HashMap::default();
    for route in &fragment.qualified_routes {
        assert!(
            qualified_route_ordinals.insert((
                route.reference,
                route.projection_output_slot,
                route.precedence_ordinal
            )),
            "qualified route (reference, output slot, precedence ordinal) must be unique"
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

fn transfer_sort_key(
    row: &LoweredTypeTransfer,
) -> (SemanticId, u8, SemanticId, i64, i64, SemanticId) {
    (
        row.source_slot,
        transfer_kind_rank(row.kind),
        row.rule.target_slot(),
        row.rule.indirection_delta(),
        row.rule.reference_indirection_delta(),
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
) -> (
    SemanticId,
    u32,
    u8,
    SemanticId,
    SemanticId,
    SemanticId,
    SemanticId,
) {
    (
        row.reference,
        row.precedence_ordinal,
        namespace_rank(row.namespace),
        row.lookup,
        row.source_lookup,
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
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-type-transfer-rule-local:v3");
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
        ResolutionTypeTransferValueTransform::TypeObjectOnly => {
            hasher.field("value_transform", b"type-object-only");
        }
        ResolutionTypeTransferValueTransform::AddressableRuntimeOnly => {
            hasher.field("value_transform", b"addressable-runtime-only");
        }
        ResolutionTypeTransferValueTransform::AddressableOperandOnly => {
            hasher.field("value_transform", b"addressable-operand-only");
        }
        ResolutionTypeTransferValueTransform::RuntimeOnly => {
            hasher.field("value_transform", b"runtime-only");
        }
    }
    hasher.field(
        "indirection_delta",
        &i64::from(fact.indirection_delta).to_be_bytes(),
    );
    hasher.field(
        "reference_indirection_delta",
        &i64::from(fact.reference_indirection_delta).to_be_bytes(),
    );
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
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

const fn projection_kind_rank(kind: BindingProjectionKind) -> u8 {
    match kind {
        BindingProjectionKind::TargetTypeIdentity => 0,
        BindingProjectionKind::TargetDeclaredValueType => 1,
        BindingProjectionKind::TargetCallableResultType => 2,
        BindingProjectionKind::TargetConstructorOwnerType => 3,
        BindingProjectionKind::TargetTypeOrDeclaredValueType => 4,
        BindingProjectionKind::TargetMemberOwnerType => 5,
        BindingProjectionKind::TargetNominalTypeIdentity => 6,
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
        ResolutionNamespace::Package => 7,
    }
}

const fn transfer_kind_rank(kind: ResolutionTypeTransferKind) -> u8 {
    match kind {
        ResolutionTypeTransferKind::TypeIdentity => 0,
        ResolutionTypeTransferKind::TypeAlias => 9,
        ResolutionTypeTransferKind::TypeUnion => 10,
        ResolutionTypeTransferKind::DeclaredType => 1,
        ResolutionTypeTransferKind::Initialization => 2,
        ResolutionTypeTransferKind::Assignment => 3,
        ResolutionTypeTransferKind::Construction => 4,
        ResolutionTypeTransferKind::Receiver => 5,
        ResolutionTypeTransferKind::Argument => 6,
        ResolutionTypeTransferKind::Return => 7,
        // Appended rather than inserted next to `Initialization`: this rank is
        // hashed into every transfer's semantic identity, so renumbering the
        // existing kinds would change identities no part of this change means
        // to move.
        ResolutionTypeTransferKind::Unwrap => 8,
        ResolutionTypeTransferKind::UnaryIndirection => 11,
        ResolutionTypeTransferKind::AddressOf => 12,
        ResolutionTypeTransferKind::ComponentElement => 13,
        ResolutionTypeTransferKind::ComponentKey => 14,
        ResolutionTypeTransferKind::ComponentValue => 15,
    }
}

const fn intrinsic_kind_rank(kind: IntrinsicTypeKind) -> u8 {
    match kind {
        IntrinsicTypeKind::Primitive => 0,
        IntrinsicTypeKind::LanguageBuiltin => 1,
        IntrinsicTypeKind::Slice => 2,
        IntrinsicTypeKind::Array => 3,
        IntrinsicTypeKind::Structural => 4,
    }
}

const fn declaration_type_role_rank(role: DeclarationTypeRole) -> u8 {
    match role {
        DeclarationTypeRole::Value => 0,
        DeclarationTypeRole::Parameter => 1,
        DeclarationTypeRole::Return => 2,
        DeclarationTypeRole::Identity => 3,
        DeclarationTypeRole::NominalIdentity => 4,
    }
}

const fn member_kind_rank(kind: ResolutionMemberKind) -> u8 {
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

const fn member_qualifier_compatibility_rank(
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
        ResolutionSupertypeKind::GoInterfaceElement => 2,
        ResolutionSupertypeKind::ImplicitSuperclass => 3,
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
        ResolutionGapKind::UnprovenActivation => 16,
        ResolutionGapKind::GeneratedItemSurface => 17,
        ResolutionGapKind::MacroArgument => 18,
        ResolutionGapKind::UnexpandedItemMacro => 19,
        ResolutionGapKind::UnexpandedImplMacro => 20,
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::resolution::fact_lowering::fixture_names::{
        definition_semantic, gap_reason_semantic, reference_semantic, scope_head_node,
        site_type_frontier_semantic, type_slot_semantic,
    };

    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionFact, DeclarationTypeSlotFact, IntrinsicTypeSeedFact,
        PositionedIdentifierFact, ResolutionCallFact, ResolutionConstructionRequirementFact,
        ResolutionDeclarationVisibilityFact, ResolutionGapFact, ResolutionIdentifierRole,
        ResolutionMemberOwnerFact, ResolutionNameFact, ResolutionNameId, ResolutionScopeFact,
        ResolutionScopeId, ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact,
        ResolutionSiteId, ResolutionSiteKind, ResolutionSupertypeFact, ResolutionTypeSlotFact,
        ResolutionTypeSlotId, ResolutionTypeTransferFact, ResolutionVisibilityEligibilityFact,
    };

    use super::super::model::TypeTransferApplication;
    use super::*;

    fn fragment() -> BindingFragmentId {
        BindingFragmentId::for_test(b"typed-fact-lowering-test-fragment")
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
            inheritance: ResolutionScopeInheritance::Lexical,
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
            reference_indirection_delta: 0,
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
                result_types: Vec::new(),
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
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: 0,
            }],
            callable_signatures: vec![ResolutionCallableSignatureFact {
                callable: ResolutionSiteId::new(1),
                type_parameter_count: 0,
                result_types: Vec::new(),
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

    fn initialization_facts() -> FileResolutionFacts {
        let mut facts = constructor_facts();
        let declaration = ResolutionSiteId::new(5);
        let target = ResolutionTypeSlotId::new(2);
        facts.names.push(name(1, "service"));
        facts
            .sites
            .push(site(5, 0, ResolutionSiteKind::ValueDeclaration, 95));
        facts.identifiers.push(identifier(
            5,
            1,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        ));
        facts
            .type_slots
            .push(slot(2, 5, ResolutionTypeSlotRole::DeclaredValue));
        facts.declaration_type_slots.push(DeclarationTypeSlotFact {
            declaration,
            slot: target,
            role: DeclarationTypeRole::Value,
        });
        facts.type_transfers.push(transfer(
            1,
            2,
            ResolutionTypeTransferKind::Initialization,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        ));
        facts
    }

    /// `let service = make()?;`: the call result is unwrapped into an
    /// intermediate call result owned by the declaration, which the zero-delta
    /// initialization transfer then carries into the binding.
    fn unwrap_facts() -> FileResolutionFacts {
        let mut facts = initialization_facts();
        facts
            .type_slots
            .push(slot(3, 5, ResolutionTypeSlotRole::CallResult));
        facts.type_transfers.push(transfer(
            1,
            3,
            ResolutionTypeTransferKind::Unwrap,
            -1,
            ResolutionTypeTransferValueTransform::Preserve,
        ));
        facts
            .type_transfers
            .iter_mut()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::Initialization)
            .expect("initialization facts carry one initialization transfer")
            .input = ResolutionTypeSlotId::new(3);
        facts
    }

    fn qualified_callable_facts(namespace: ResolutionNamespace) -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![name(0, "Receiver"), name(1, "target")],
            scopes: vec![scope(
                0,
                None,
                None,
                ResolutionScopeKind::CompilationUnit,
                0,
                100,
            )],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeReference, 1),
                site(1, 0, ResolutionSiteKind::MemberReference, 2),
                site(2, 0, ResolutionSiteKind::Call, 3),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    namespace,
                    Some(0),
                ),
            ],
            type_slots: vec![
                slot(0, 0, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 2, ResolutionTypeSlotRole::CallResult),
            ],
            binding_projections: vec![
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(0),
                    output: ResolutionTypeSlotId::new(0),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(1),
                    output: ResolutionTypeSlotId::new(1),
                    kind: BindingProjectionKind::TargetCallableResultType,
                },
            ],
            calls: vec![ResolutionCallFact {
                call: ResolutionSiteId::new(2),
                callee: ResolutionSiteId::new(1),
                receiver: None,
                result: ResolutionTypeSlotId::new(1),
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: 0,
            }],
            ..FileResolutionFacts::default()
        }
    }

    #[test]
    fn callable_routes_preserve_member_dispatch_and_register_independent_source_lookup() {
        for language in [Language::Java, Language::Go, Language::Rust] {
            for namespace in [ResolutionNamespace::Value, ResolutionNamespace::Callable] {
                let facts = qualified_callable_facts(namespace);
                assert!(
                    facts.root_references.is_empty(),
                    "ordinary qualified reference fixture"
                );
                let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                    fragment(),
                    crate::analyzer::resolution::test_shared_names(),
                    language,
                    &facts,
                );
                let typed = artifact.typed();
                assert_eq!(typed.qualified_routes().len(), 1);
                let route = &typed.qualified_routes()[0];
                assert_eq!(
                    route.lookup(),
                    lookup_semantic(
                        crate::analyzer::resolution::test_shared_names(),
                        language,
                        ResolutionNamespace::Callable,
                        "target"
                    )
                );
                assert_eq!(route.namespace(), ResolutionNamespace::Callable);
                assert_eq!(
                    route.source_lookup(),
                    lookup_semantic(
                        crate::analyzer::resolution::test_shared_names(),
                        language,
                        namespace,
                        "target"
                    )
                );
                assert_eq!(
                    route.projection_kind(),
                    BindingProjectionKind::TargetCallableResultType
                );
                let recipe = artifact
                    .identities()
                    .lookup_recipe(route.source_lookup())
                    .unwrap();
                assert_eq!(recipe.namespace(), namespace);
                assert_eq!(recipe.spelling(), "target");
                if namespace == ResolutionNamespace::Value {
                    assert!(
                        artifact.lexical().paths().iter().all(|(_, path)| {
                            [path.start(), path.end()].iter().all(|endpoint| {
                                endpoint
                                    .symbols()
                                    .fixed()
                                    .iter()
                                    .all(|symbol| symbol.symbol() != route.source_lookup())
                            })
                        }),
                        "non-root qualified lookup is absent from symbol-free lexical gap paths"
                    );
                }
                assert_eq!(
                    route.lookup() == route.source_lookup(),
                    namespace == ResolutionNamespace::Callable
                );
                assert_eq!(hydrated_clone(typed), *typed);
                let remounted = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                    BindingFragmentId::for_test(b"another-selected-mount"),
                    crate::analyzer::resolution::test_shared_names(),
                    language,
                    &facts,
                );
                let other = &remounted.typed().qualified_routes()[0];
                assert_ne!(route.reference(), other.reference());
                assert_eq!(route.lookup(), other.lookup());
                assert_eq!(route.source_lookup(), other.source_lookup());
            }
        }
    }

    #[test]
    #[should_panic(
        expected = "qualified route (reference, output slot, precedence ordinal) must be unique"
    )]
    fn source_lookup_does_not_create_a_second_identity_for_the_same_qualified_route() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Rust,
            &qualified_callable_facts(ResolutionNamespace::Value),
        )
        .typed()
        .clone();
        let mut conflicting = lowered.qualified_routes[0];
        conflicting.source_lookup = conflicting.lookup;
        assert_ne!(conflicting, lowered.qualified_routes[0]);
        lowered.qualified_routes.push(conflicting);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "only callable result or method-value projections may separate source and member lookup"
    )]
    fn constructor_route_cannot_invent_a_different_source_lookup() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
        lowered.qualified_routes[0].source_lookup = SemanticId::for_test(b"wrong-source-lookup");
        let _ = renormalize_hydrated(lowered);
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
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
            reversed(lowered.intrinsic_seeds().iter().map(|row| {
                LoweredIntrinsicSeed::new(row.kind(), row.spelling(), row.frontier().clone())
            })),
            reversed(lowered.projections().iter().map(|row| {
                LoweredBindingProjection::new(row.reference(), row.output_slot(), row.kind())
            })),
            reversed(lowered.qualified_routes().iter().map(|row| {
                LoweredQualifiedSeededRoute::new_with_source_lookup(
                    row.reference(),
                    row.qualifier_slot(),
                    row.lookup(),
                    row.namespace(),
                    row.source_lookup(),
                    row.precedence_ordinal(),
                    row.projection_output_slot(),
                    row.projection_kind(),
                    row.coarse_gap_reason(),
                    row.open_member_surface(),
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
            reversed(lowered.deferred_member_owners().iter().map(|row| {
                LoweredDeferredMemberOwner::new(
                    row.definition(),
                    row.owner_frontier(),
                    row.lookup(),
                    row.kind(),
                    row.access(),
                    row.qualifier_compatibility(),
                )
                .with_hierarchy_frontier(row.hierarchy_frontier())
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
        } = lowered;
        LoweredTypedFragment::new_with_type_relations(
            fragment,
            language,
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
            for &argument in obligation
                .type_argument_slots()
                .iter()
                .chain(obligation.owner_type_argument_slots())
                .chain(obligation.expected_result_slot().iter())
                .chain(obligation.owner_type_segment().iter())
            {
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
            Vec::new(),
        )
    }

    fn hydrated_intrinsic_fragment(
        role: ResolutionTypeSlotRole,
        values: Vec<ResolutionSlotValue>,
        completion: ResolutionCompletion,
    ) -> LoweredTypedFragment {
        let slot = SemanticId::for_test(b"hydrated-intrinsic-slot");
        minimal_hydrated_fragment(
            vec![LoweredTypedFrontier::new(slot, role)],
            Vec::new(),
            vec![LoweredIntrinsicSeed::new(
                IntrinsicTypeKind::LanguageBuiltin,
                "test_intrinsic",
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

        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
            let lowered =
                crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                    .typed()
                    .clone();
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
            let expected =
                crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                    .typed()
                    .clone();
            assert_eq!(hydrated_clone(&expected), expected);
        }
    }

    #[test]
    fn non_java_source_visibility_inventory_uses_the_common_property_family() {
        let facts = constructor_facts();
        let lowered = crate::analyzer::resolution::lower_for_test(fragment(), Language::Go, &facts)
            .typed()
            .clone();
        assert_eq!(
            lowered.declaration_visibilities().len(),
            facts.declaration_visibilities.len()
        );
    }

    #[test]
    fn non_java_hydrated_visibility_inventory_uses_the_common_property_family() {
        let mut hydrated = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
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
            SemanticId::for_test(b"duplicate-frontier"),
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ =
            minimal_hydrated_fragment(vec![frontier, frontier], Vec::new(), Vec::new(), Vec::new());
    }

    #[test]
    #[should_panic(expected = "type-transfer target names undeclared typed frontier")]
    fn hydration_rejects_a_row_owned_slot_missing_from_the_inventory() {
        let source = SemanticId::for_test(b"declared-source");
        let target = SemanticId::for_test(b"missing-target");
        let transfer = LoweredTypeTransfer::new(
            source,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                SemanticId::for_test(b"transfer"),
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
        let source = SemanticId::for_test(b"producer-source");
        let output = SemanticId::for_test(b"producer-output");
        let transfer = LoweredTypeTransfer::new(
            source,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                SemanticId::for_test(b"producer-transfer"),
                output,
                0,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        );
        let projection = LoweredBindingProjection::new(
            SemanticId::for_test(b"producer-reference"),
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
            SemanticId::for_test(b"callable"),
            0,
            vec![LoweredCallableParameterProperty::new(
                1,
                SemanticId::for_test(b"parameter"),
                SemanticId::for_test(b"parameter-slot"),
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
                    SemanticId::for_test([b"parameter-definition".as_slice(), &bytes].concat()),
                    SemanticId::for_test([b"parameter-slot".as_slice(), &bytes].concat()),
                    ordinal == 299,
                )
            })
            .collect::<Vec<_>>();
        let completion = ResolutionCompletion::incomplete((0_u32..300).map(|ordinal| {
            let bytes = ordinal.to_le_bytes();
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                [b"signature-reason".as_slice(), &bytes].concat(),
            ))
        }));
        let signature = LoweredCallableSignatureProperty::new(
            SemanticId::for_test(b"polled-signature"),
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
            signature.result_types().to_vec().into_boxed_slice(),
            signature.result_bindings().to_vec().into_boxed_slice(),
            signature.receiver(),
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
            SemanticId::for_test(b"completion-only-polled-signature"),
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
        lowered.projections.clear();
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "member owner must name its declaring type's exact member scope")]
    fn hydration_rejects_a_member_owner_without_its_scope_property() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
        lowered.call_obligations[0].completion = ResolutionCompletion::Complete;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "intrinsic type seed completion cannot persist operation-local cancellation"
    )]
    fn hydration_rejects_operation_local_cancellation_evidence() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
        set_first_intrinsic_completion(
            &mut lowered,
            ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into()),
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "incomplete reasons must be strictly sorted and unique")]
    fn hydration_rejects_noncanonical_incomplete_reason_order() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
        let mut reasons = vec![
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"first")),
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"second")),
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
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
        let ty = ResolutionTypeRef::new(SemanticId::for_test(b"runtime-not-type-object"), 0);
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
                    SemanticId::for_test(b"first-intrinsic-type"),
                    0,
                )),
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    SemanticId::for_test(b"second-intrinsic-type"),
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
        let ty = ResolutionTypeRef::new(SemanticId::for_test(b"addressable-intrinsic"), 0);
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
        let reason = SemanticId::for_test(b"unsupported-intrinsic-role");
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
        let output = lowered.projections[0].output_slot;
        set_frontier_role(
            &mut lowered,
            output,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "declaration type property must retain its declared category")]
    fn hydration_rejects_a_declaration_property_with_the_wrong_slot_role() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
        let slot = lowered.declaration_types[0].slot;
        set_frontier_role(&mut lowered, slot, ResolutionTypeSlotRole::AssignmentValue);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "supertype property must name a TargetTypeIdentity frontier")]
    fn hydration_rejects_a_supertype_with_the_wrong_frontier_role() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
        let frontier = SemanticId::for_test(b"wrong-role-supertype-frontier");
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
        lowered.projections.clear();
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "call result must name a CallResult frontier")]
    fn hydration_rejects_a_call_result_with_the_wrong_role() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
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
        expected = "callable parameter's Parameter declaration type property must name its slot"
    )]
    fn hydration_rejects_a_callable_parameter_whose_declaration_property_names_another_slot() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
        let first = lowered.callable_signatures[0].parameters[0];
        let second = lowered.callable_signatures[0].parameters[1];
        for property in &mut lowered.declaration_types {
            if (property.definition, property.slot) == (first.definition, first.slot) {
                property.slot = second.slot;
            } else if (property.definition, property.slot) == (second.definition, second.slot) {
                property.slot = first.slot;
            }
        }
        let _ = renormalize_hydrated(lowered);
    }

    /// An unnamed parameter (Rust `_`) binds no definition, so its row names a
    /// slot that no declaration type property carries.
    #[test]
    fn hydration_accepts_an_unnamed_callable_parameter_without_a_declaration_property() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
        let parameter = lowered.callable_signatures[0].parameters[0];
        lowered.declaration_types.retain(|property| {
            (property.definition, property.slot) != (parameter.definition, parameter.slot)
        });
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "callable parameter definition may belong to only one signature")]
    fn hydration_rejects_one_parameter_definition_shared_by_two_signatures() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &call_applicability_facts(),
        )
        .typed()
        .clone();
        let parameter = lowered.callable_signatures[0].parameters[0];
        lowered
            .callable_signatures
            .push(LoweredCallableSignatureProperty::new(
                SemanticId::for_test(b"second-callable"),
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &nested_constructor_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
        lowered.qualified_routes[0].namespace = ResolutionNamespace::Value;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "must have the exact source-lowerable namespace and precedence shape"
    )]
    fn hydration_rejects_an_incomplete_type_or_value_route_pair() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &declared_and_observed_facts(),
        )
        .typed()
        .clone();
        let semantic = lowered.transfers[0].rule.semantic();
        let replacement = {
            let duplicate = &lowered.transfers[1];
            LoweredTypeTransfer::new(
                duplicate.source_slot,
                duplicate.kind,
                TypeTransferRule::new_with_reference_indirection(
                    semantic,
                    duplicate.rule.target_slot(),
                    duplicate.rule.indirection_delta(),
                    duplicate.rule.reference_indirection_delta(),
                    duplicate.rule.value_transform(),
                    duplicate.rule.completion().clone(),
                ),
            )
        };
        lowered.transfers[1] = replacement;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "qualified route (reference, output slot, precedence ordinal) must be unique"
    )]
    fn hydration_rejects_duplicate_qualified_route_ordinals() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
        let duplicate = lowered.qualified_routes[0];
        lowered.qualified_routes.push(duplicate);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(
        expected = "qualified-route coarse gap reason may belong to only one reference per fragment"
    )]
    fn hydration_rejects_one_coarse_gap_reason_reused_by_two_references() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &constructor_facts(),
        )
        .typed()
        .clone();
        let mut second_reference = lowered.qualified_routes[0];
        second_reference.reference = SemanticId::for_test(b"second-qualified-reference");
        lowered.qualified_routes.push(second_reference);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "member-scope head may belong to only one type definition")]
    fn hydration_rejects_a_member_scope_head_shared_by_two_definitions() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &nested_constructor_facts(),
        )
        .typed()
        .clone();
        assert!(lowered.member_scopes.len() >= 2);
        let shared_head = lowered.member_scopes[0].scope_head;
        lowered.member_scopes[1].scope_head = shared_head;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "definition property-gap SQL identity must be unique")]
    fn hydration_rejects_duplicate_property_gap_sql_identities() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
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
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
        let mut conflicting = lowered.property_gaps[0];
        conflicting.definition = SemanticId::for_test(b"conflicting-property-gap-owner");
        lowered.property_gaps.push(conflicting);
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    #[should_panic(expected = "definition property gap kind is not source-lowerable")]
    fn hydration_rejects_an_unsupported_definition_property_gap_kind() {
        let mut lowered = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Java,
            &hierarchy_facts(),
        )
        .typed()
        .clone();
        lowered.property_gaps[0].kind = ResolutionGapKind::UnsupportedExpression;
        let _ = renormalize_hydrated(lowered);
    }

    #[test]
    fn declared_base_types_remain_separate_from_observed_sub_values() {
        let facts = declared_and_observed_facts();
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
            .find(|transfer| transfer.kind() == ResolutionTypeTransferKind::DeclaredType)
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
        let base = base_type.frontier().possible_values()[0];
        assert!(matches!(
            declared.rule().apply(base),
            TypeTransferApplication::Value(ResolutionSlotValue::Runtime { .. })
        ));
        assert_eq!(
            observed
                .rule()
                .apply(sub_value.frontier().possible_values()[0]),
            TypeTransferApplication::Value(sub_value.frontier().possible_values()[0])
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
            lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Java,
                ResolutionNamespace::Constructor,
                "Sub"
            )
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
        let obligation = &lowered.call_obligations()[0];
        // The call's own semantic is not a site's, so it has no number of its
        // own to recompute; what the row has to satisfy is that it is this
        // mount's and is not the callee's.
        assert_eq!(obligation.call().ordinal(), Some(fragment().ordinal()));
        assert_ne!(obligation.call(), obligation.callee_reference());
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
        let unsupported = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(7))
            })
            .expect("unsupported intrinsic role remains represented");
        let base = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0))
            })
            .expect("first intrinsic seed remains represented");
        let sub = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| {
                seed.frontier().slot()
                    == type_slot_semantic(fragment(), ResolutionTypeSlotId::new(2))
            })
            .expect("second intrinsic seed remains represented");
        assert_eq!(base.spelling(), "Base");
        assert_eq!(sub.spelling(), "Sub");
        assert_ne!(
            base.frontier().possible_values()[0].ty().identity(),
            sub.frontier().possible_values()[0].ty().identity(),
            "distinct intrinsic spellings retain distinct shared identities"
        );
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
        let lowered = crate::analyzer::resolution::lower_for_test(fragment(), Language::Go, &facts)
            .typed()
            .clone();
        let rule = lowered.transfers()[0].rule();
        assert_eq!(rule.indirection_delta(), -1);
        let input = lowered.intrinsic_seeds()[0].frontier().possible_values()[0];
        let TypeTransferApplication::Value(decremented) = rule.apply(input) else {
            panic!("2 - 1 is representable")
        };
        assert_eq!(decremented.ty().indirection(), 1);

        facts.type_transfers[0].indirection_delta = 1;
        let incremented =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Go, &facts)
                .typed()
                .clone();
        assert_eq!(incremented.transfers()[0].rule().indirection_delta(), 1);
        let TypeTransferApplication::Value(incremented_value) =
            incremented.transfers()[0].rule().apply(input)
        else {
            panic!("2 + 1 is representable")
        };
        assert_eq!(incremented_value.ty().indirection(), 3);
    }

    #[test]
    fn reference_provenance_is_lowered_applied_and_identity_significant() {
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
            type_transfers: vec![ResolutionTypeTransferFact {
                input: ResolutionTypeSlotId::new(0),
                output: ResolutionTypeSlotId::new(1),
                kind: ResolutionTypeTransferKind::Assignment,
                indirection_delta: 1,
                reference_indirection_delta: 1,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            }],
            intrinsic_type_seeds: vec![IntrinsicTypeSeedFact {
                output: ResolutionTypeSlotId::new(0),
                name: ResolutionNameId::new(0),
                kind: IntrinsicTypeKind::LanguageBuiltin,
                indirection: 2,
            }],
            ..FileResolutionFacts::default()
        };
        let reference =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Rust, &facts)
                .typed()
                .clone();
        let reference_rule = reference.transfers()[0].rule();
        assert_eq!(reference_rule.reference_indirection_delta(), 1);
        let input = reference.intrinsic_seeds()[0].frontier().possible_values()[0];
        let TypeTransferApplication::Value(mixed) = reference_rule.apply(input) else {
            panic!("the reference adjustment is representable")
        };
        assert_eq!(mixed.ty().indirection(), 3);
        assert_eq!(mixed.ty().reference_indirection(), 1);
        assert!(!mixed.ty().has_only_reference_indirection());

        facts.type_transfers[0].reference_indirection_delta = 0;
        let raw = crate::analyzer::resolution::lower_for_test(fragment(), Language::Rust, &facts)
            .typed()
            .clone();
        assert_ne!(
            reference_rule.semantic(),
            raw.transfers()[0].rule().semantic(),
            "reference provenance participates in transfer-rule identity"
        );
    }

    #[test]
    fn type_identity_transfer_preserves_an_occurrence_owned_type_frontier() {
        let facts = FileResolutionFacts {
            names: vec![name(0, "Service")],
            scopes: vec![scope(
                0,
                None,
                None,
                ResolutionScopeKind::CompilationUnit,
                0,
                20,
            )],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeReference, 1),
                site(1, 0, ResolutionSiteKind::TypeReference, 2),
            ],
            type_slots: vec![
                slot(0, 0, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 1, ResolutionTypeSlotRole::TargetTypeIdentity),
            ],
            type_transfers: vec![ResolutionTypeTransferFact {
                input: ResolutionTypeSlotId::new(0),
                output: ResolutionTypeSlotId::new(1),
                kind: ResolutionTypeTransferKind::TypeIdentity,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            }],
            intrinsic_type_seeds: vec![IntrinsicTypeSeedFact {
                output: ResolutionTypeSlotId::new(0),
                name: ResolutionNameId::new(0),
                kind: IntrinsicTypeKind::LanguageBuiltin,
                indirection: 0,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Rust, &facts)
                .typed()
                .clone();
        let transfer = &lowered.transfers()[0];
        assert_eq!(transfer.kind(), ResolutionTypeTransferKind::TypeIdentity);
        let input = lowered.intrinsic_seeds()[0].frontier().possible_values()[0];
        let TypeTransferApplication::Value(output) = transfer.rule().apply(input) else {
            panic!("identity transfer preserves one value")
        };
        assert_eq!(output, input);
    }

    #[test]
    fn initialization_transfer_contract_is_enforced_at_source() {
        let valid = initialization_facts();
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Rust, &valid)
                .typed()
                .clone();
        let initialization = lowered
            .transfers()
            .iter()
            .find(|transfer| transfer.kind() == ResolutionTypeTransferKind::Initialization)
            .expect("lowered initialization transfer");
        assert_eq!(initialization.rule().indirection_delta(), 0);
        assert_eq!(initialization.rule().reference_indirection_delta(), 0);
        assert_eq!(
            initialization.rule().value_transform(),
            TypeTransferValueTransform::Preserve
        );

        let mut nonzero = valid.clone();
        let nonzero_transfer = nonzero.type_transfers.last_mut().unwrap();
        nonzero_transfer.indirection_delta = 1;
        nonzero_transfer.reference_indirection_delta = 1;
        let mut wrong_category = valid.clone();
        wrong_category
            .type_transfers
            .last_mut()
            .unwrap()
            .value_transform =
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false };
        let mut wrong_source_role = valid.clone();
        wrong_source_role.type_transfers.last_mut().unwrap().input = ResolutionTypeSlotId::new(0);
        let mut wrong_target_role = valid.clone();
        wrong_target_role
            .type_slots
            .push(slot(3, 5, ResolutionTypeSlotRole::AssignmentValue));
        wrong_target_role
            .declaration_type_slots
            .last_mut()
            .unwrap()
            .slot = ResolutionTypeSlotId::new(3);
        wrong_target_role.type_transfers.last_mut().unwrap().output = ResolutionTypeSlotId::new(3);

        for invalid in [
            nonzero,
            wrong_category,
            wrong_source_role,
            wrong_target_role,
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    crate::analyzer::resolution::lower_for_test(
                        fragment(),
                        Language::Rust,
                        &invalid,
                    )
                    .typed()
                    .clone()
                })
                .is_err(),
                "invalid source initialization transfer must be rejected"
            );
        }
    }

    #[test]
    fn initialization_transfer_contract_is_enforced_after_hydration() {
        let valid = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Rust,
            &initialization_facts(),
        )
        .typed()
        .clone();
        let initialization_index = valid
            .transfers
            .iter()
            .position(|transfer| transfer.kind == ResolutionTypeTransferKind::Initialization)
            .expect("lowered initialization transfer");

        let mut nonzero = valid.clone();
        let prior = nonzero.transfers[initialization_index].rule().clone();
        nonzero.transfers[initialization_index].rule =
            TypeTransferRule::new_with_reference_indirection(
                prior.semantic(),
                prior.target_slot(),
                1,
                1,
                prior.value_transform(),
                prior.completion().clone(),
            );
        let mut wrong_category = valid.clone();
        let prior = wrong_category.transfers[initialization_index]
            .rule()
            .clone();
        wrong_category.transfers[initialization_index].rule =
            TypeTransferRule::new_with_reference_indirection(
                prior.semantic(),
                prior.target_slot(),
                0,
                0,
                TypeTransferValueTransform::ToRuntime { addressable: false },
                prior.completion().clone(),
            );
        let mut wrong_source_role = valid.clone();
        wrong_source_role.transfers[initialization_index].source_slot =
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0));
        let mut wrong_target_role = valid.clone();
        let invalid_target = SemanticId::for_test(b"invalid-initialization-target-role");
        wrong_target_role.frontiers.push(LoweredTypedFrontier::new(
            invalid_target,
            ResolutionTypeSlotRole::AssignmentValue,
        ));
        let prior = wrong_target_role.transfers[initialization_index]
            .rule()
            .clone();
        wrong_target_role.transfers[initialization_index].rule =
            TypeTransferRule::new_with_reference_indirection(
                prior.semantic(),
                invalid_target,
                prior.indirection_delta(),
                prior.reference_indirection_delta(),
                prior.value_transform(),
                prior.completion().clone(),
            );

        for invalid in [
            nonzero,
            wrong_category,
            wrong_source_role,
            wrong_target_role,
        ] {
            assert!(
                std::panic::catch_unwind(|| renormalize_hydrated(invalid)).is_err(),
                "invalid hydrated initialization transfer must be rejected"
            );
        }
    }

    #[test]
    fn unwrap_transfer_contract_is_enforced_at_source() {
        let valid = unwrap_facts();
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Rust, &valid)
                .typed()
                .clone();
        let unwrap = lowered
            .transfers()
            .iter()
            .find(|transfer| transfer.kind() == ResolutionTypeTransferKind::Unwrap)
            .expect("lowered unwrap transfer");
        assert_eq!(unwrap.rule().indirection_delta(), -1);
        assert_eq!(unwrap.rule().reference_indirection_delta(), 0);
        assert_eq!(
            unwrap.rule().value_transform(),
            TypeTransferValueTransform::Preserve
        );

        let unwrap_index = valid
            .type_transfers
            .iter()
            .position(|transfer| transfer.kind == ResolutionTypeTransferKind::Unwrap)
            .expect("source unwrap transfer");
        // A positive delta would add a layer the encoding never wrote.
        let mut positive_delta = valid.clone();
        positive_delta.type_transfers[unwrap_index].indirection_delta = 1;
        // A reference delta would claim the discharged layer was a borrow.
        let mut reference_delta = valid.clone();
        reference_delta.type_transfers[unwrap_index].reference_indirection_delta = -1;
        let mut wrong_category = valid.clone();
        wrong_category.type_transfers[unwrap_index].value_transform =
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false };
        // A type object is not an unwrappable operand.
        let mut wrong_source_role = valid.clone();
        wrong_source_role.type_transfers[unwrap_index].input = ResolutionTypeSlotId::new(0);
        // The output must be a call result, so `Initialization` can take it.
        let mut wrong_target_role = valid.clone();
        wrong_target_role.type_slots[3] = slot(3, 5, ResolutionTypeSlotRole::ExpressionValue);

        for invalid in [
            positive_delta,
            reference_delta,
            wrong_category,
            wrong_source_role,
            wrong_target_role,
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    crate::analyzer::resolution::lower_for_test(
                        fragment(),
                        Language::Rust,
                        &invalid,
                    )
                    .typed()
                    .clone()
                })
                .is_err(),
                "invalid source unwrap transfer must be rejected"
            );
        }
    }

    #[test]
    fn unwrap_transfer_contract_is_enforced_after_hydration() {
        let valid = crate::analyzer::resolution::lower_for_test(
            fragment(),
            Language::Rust,
            &unwrap_facts(),
        )
        .typed()
        .clone();
        let unwrap_index = valid
            .transfers
            .iter()
            .position(|transfer| transfer.kind == ResolutionTypeTransferKind::Unwrap)
            .expect("lowered unwrap transfer");
        let rebuilt = |fragment: &LoweredTypedFragment,
                       delta: i64,
                       reference_delta: i64,
                       transform: TypeTransferValueTransform,
                       target: SemanticId| {
            let prior = fragment.transfers[unwrap_index].rule().clone();
            TypeTransferRule::new_with_reference_indirection(
                prior.semantic(),
                target,
                delta,
                reference_delta,
                transform,
                prior.completion().clone(),
            )
        };

        let mut positive_delta = valid.clone();
        let target = positive_delta.transfers[unwrap_index].rule().target_slot();
        positive_delta.transfers[unwrap_index].rule = rebuilt(
            &positive_delta,
            1,
            0,
            TypeTransferValueTransform::Preserve,
            target,
        );
        let mut reference_delta = valid.clone();
        reference_delta.transfers[unwrap_index].rule = rebuilt(
            &reference_delta,
            -1,
            -1,
            TypeTransferValueTransform::Preserve,
            target,
        );
        let mut wrong_category = valid.clone();
        wrong_category.transfers[unwrap_index].rule = rebuilt(
            &wrong_category,
            -1,
            0,
            TypeTransferValueTransform::ToRuntime { addressable: false },
            target,
        );
        let mut wrong_source_role = valid.clone();
        wrong_source_role.transfers[unwrap_index].source_slot =
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0));
        let mut wrong_target_role = valid.clone();
        let invalid_target = SemanticId::for_test(b"invalid-unwrap-target-role");
        wrong_target_role.frontiers.push(LoweredTypedFrontier::new(
            invalid_target,
            ResolutionTypeSlotRole::ExpressionValue,
        ));
        wrong_target_role.transfers[unwrap_index].rule = rebuilt(
            &wrong_target_role,
            -1,
            0,
            TypeTransferValueTransform::Preserve,
            invalid_target,
        );

        for invalid in [
            positive_delta,
            reference_delta,
            wrong_category,
            wrong_source_role,
            wrong_target_role,
        ] {
            assert!(
                std::panic::catch_unwind(|| renormalize_hydrated(invalid)).is_err(),
                "invalid hydrated unwrap transfer must be rejected"
            );
        }
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
        let (input_slot, output_slot) = (declared.input, declared.output);

        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
        // After the lowering: the catalog that numbers these slots is the one
        // this lowering built, and a fixture names a position by asking it.
        let expected_source = type_slot_semantic(fragment(), input_slot);
        let expected_target = type_slot_semantic(fragment(), output_slot);
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
        let input = lowered
            .intrinsic_seeds()
            .iter()
            .find(|seed| seed.frontier().slot() == transfer.source_slot())
            .expect("typed seed")
            .frontier()
            .possible_values()[0];
        assert_eq!(rule.apply(input), TypeTransferApplication::NoValue);
    }

    #[test]
    fn implicit_constructor_and_hierarchy_gaps_are_owned_properties() {
        let mut facts = hierarchy_facts();
        facts.declaration_visibilities[0].visibility = DeclaredVisibility::PackagePrivate;
        facts.gaps.push(ResolutionGapFact {
            site: ResolutionSiteId::new(0),
            kind: ResolutionGapKind::UnsupportedVisibility,
        });
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
        let expected =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &permuted)
                .typed()
                .clone(),
            expected
        );
    }

    #[test]
    #[should_panic(expected = "unknown resolution type slot")]
    fn malformed_projection_slot_is_rejected_at_construction() {
        let mut facts = hierarchy_facts();
        facts.binding_projections[0].output = ResolutionTypeSlotId::new(99);
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
    }

    /// A hierarchy gap on a type reference that no supertype property names is
    /// a frontier-owned incompleteness: a trait's abstract `Self`, or a `dyn`,
    /// `impl Trait` or bounded head. It lowers without a definition property
    /// row rather than being rejected.
    #[test]
    fn frontier_owned_hierarchy_gap_lowers_without_a_definition_property() {
        let mut facts = hierarchy_facts();
        facts.supertypes.clear();
        let owned = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
        assert!(
            owned
                .property_gaps()
                .iter()
                .all(|gap| gap.kind() != ResolutionGapKind::UnsupportedHierarchyTraversal),
            "a frontier-owned hierarchy gap owns no definition property row"
        );
    }

    #[test]
    // One lowering runs both halves now, so the lexical half's own check on
    // the same fact rejects first; the two messages differ in wording and
    // agree on what a hierarchy gap may name.
    #[should_panic(expected = "must name a type declaration")]
    fn hierarchy_gap_on_a_value_declaration_is_rejected_at_construction() {
        let mut facts = hierarchy_facts();
        facts.supertypes.clear();
        facts.sites[1].kind = ResolutionSiteKind::ValueDeclaration;
        let _ = crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
            .typed()
            .clone();
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
        let lowered =
            crate::analyzer::resolution::lower_for_test(fragment(), Language::Java, &facts)
                .typed()
                .clone();
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
