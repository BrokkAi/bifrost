//! The typed-fact rows of milestone 5's draft section 6: one table per fact
//! type, how a lowered typed fragment is encoded on the way in and decoded on
//! the way out.
//!
//! Milestone 6 port block 4 (lane TF). This module is the one place that knows
//! the typed row encoding, so the writer in `store/resolution.rs` and the
//! reader in `store/resolution_typed.rs` speak the same one.
//!
//! ## Why a typed read opens no interior page
//!
//! A column that holds a blob-local semantic, node or site holds its local
//! key, and a local key **is** the low half of the runtime identity
//! (milestone 4 stage 1b-ii): `SemanticId::local(mount ordinal, key)`. So a
//! typed row decodes with the mount's ordinal and nothing else, where the path
//! body still walks the blob's identity catalog. The identity space of every
//! column is fixed by the draft's section 1 (references, definitions, slots,
//! frontiers and reasons are local; lookups and type identities are shared),
//! and the writer asserts it rather than storing a discriminator.
//!
//! ## Inside a JSONB body a symbol is one signed number
//!
//! The draft's rule for a path body applies here for the same reason: a body
//! is read by one Rust decoder and by no SQL, and a two-slot pair would double
//! the most numerous value. `>= 0` is a blob-local key, `< 0` is minus a
//! `resolution_identities.id`. That is also what lets a completion blob carry
//! a reason whose semantic may be either kind without a catalog.
//!
//! Interning happens in the writer's transaction, so the encoder emits
//! [`PathBodyToken`]s with every shared name a slot in
//! [`PreparedTypedRows::shared`] and the writer renders them once the ids
//! exist, exactly as `resolution_rows` does for a path body.

use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_BINDING_PROJECTION_KINDS, ALL_DECLARATION_TYPE_ROLES, ALL_INTRINSIC_TYPE_KINDS,
    ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS, ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
    ALL_RESOLUTION_ENGINE_RULE_KINDS, ALL_RESOLUTION_GAP_KINDS, ALL_RESOLUTION_MEMBER_ACCESSES,
    ALL_RESOLUTION_MEMBER_KINDS, ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
    ALL_RESOLUTION_SUPERTYPE_KINDS, ALL_RESOLUTION_TYPE_COMPONENT_KINDS,
    ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS, ALL_RESOLUTION_TYPE_SLOT_ROLES,
    ALL_RESOLUTION_TYPE_TRANSFER_KINDS, ResolutionEngineRuleKind, ResolutionMemberAccess,
    ResolutionMemberKind, ResolutionMemberQualifierCompatibility, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BOUNDARY_STATUSES, ALL_RESOLUTION_COMPLETION_REASON_KINDS,
};

use crate::analyzer::resolution::{
    BindingFragmentId, LoweredBindingProjection, LoweredCallApplicabilityObligation,
    LoweredCallableParameterProperty, LoweredCallableResultBinding,
    LoweredCallableResultTypeProperty, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeferredMemberOwner, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredQualifiedSeededRoute, LoweredSupertypeProperty, LoweredTypeComponent,
    LoweredTypeTransfer, LoweredTypedFragment, LoweredTypedFrontier, LoweredUnderlyingType,
    PartialPathId, ResolutionCompletion, ResolutionIdentityCatalog, ResolutionIncompleteReason,
    ResolutionSlotValue, ResolutionTypeRef, SemanticId, SharedNameId, SharedNameInterner,
    TypeTransferRule, TypeTransferValueTransform, TypedFrontierState,
};

use crate::hash::HashMap;

use super::ResolutionLocalKeys;
use super::resolution_rows::{PathBodyToken, SharedNames, code, from_code, namespace_code};

// ---------------------------------------------------------------------------
// The statements this block adds
// ---------------------------------------------------------------------------

/// Every statement below seeks a primary key or a named index with `blob_id`
/// fixed and the request's keys delivered as one JSON array, which is
/// milestone 6's rule for a reader that already holds every key it wants.
/// `json_each` is the batch; the seek is the index the comment names.
pub(crate) const TYPE_FRONTIERS_BY_SLOT_SQL: &str = "SELECT slot, role, identity_reference \
     FROM resolution_type_frontiers \
     WHERE blob_id = ?1 AND slot IN (SELECT value FROM json_each(?2))";

pub(crate) const TYPE_FRONTIERS_BY_REFERENCE_SQL: &str = "SELECT slot, role, identity_reference FROM resolution_type_frontiers \
     INDEXED BY resolution_type_frontiers_reference \
     WHERE blob_id = ?1 AND identity_reference IN (SELECT value FROM json_each(?2))";

pub(crate) const TYPE_TRANSFERS_BY_SOURCE_SQL: &str = "SELECT source_slot, rule, target_slot, kind, indirection_delta, \
            reference_indirection_delta, value_transform, json(completion) \
     FROM resolution_type_transfers \
     WHERE blob_id = ?1 AND source_slot IN (SELECT value FROM json_each(?2)) \
     ORDER BY source_slot, rule";

pub(crate) const TYPE_TRANSFERS_BY_TARGET_SQL: &str = "SELECT source_slot, rule, target_slot, kind, indirection_delta, \
            reference_indirection_delta, value_transform, json(completion) \
     FROM resolution_type_transfers INDEXED BY resolution_type_transfers_target \
     WHERE blob_id = ?1 AND target_slot IN (SELECT value FROM json_each(?2)) \
     ORDER BY target_slot, source_slot, rule";

pub(crate) const TYPE_COMPONENTS_BY_CONTAINER_SQL: &str = "SELECT container_slot, constructor, kind, component_slot \
     FROM resolution_type_components \
     WHERE blob_id = ?1 AND container_slot IN (SELECT value FROM json_each(?2)) \
     ORDER BY container_slot, kind";

pub(crate) const UNDERLYING_TYPES_BY_DEFINITION_SQL: &str = "SELECT definition, slot \
     FROM resolution_underlying_types \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2))";

pub(crate) const INTRINSIC_SEEDS_BY_SLOT_SQL: &str = "SELECT slot, kind, spelling, json(possible_values), json(completion) \
     FROM resolution_intrinsic_seeds \
     WHERE blob_id = ?1 AND slot IN (SELECT value FROM json_each(?2))";

/// Published seeds have at most one value: LoweredTypedFragment validates this
/// in assert_intrinsic_seed_matches_role, so the identity join cannot duplicate
/// a seed when a request contains several identities.
pub(crate) const INTRINSIC_SEEDS_BY_IDENTITY_SQL: &str = "SELECT seed.slot, seed.kind, seed.spelling, json(seed.possible_values), json(seed.completion) \
     FROM resolution_intrinsic_seed_identities AS named \
     JOIN resolution_intrinsic_seeds AS seed \
       ON seed.blob_id = named.blob_id AND seed.slot = named.slot \
     WHERE named.blob_id = ?1 AND named.identity_id IN (SELECT value FROM json_each(?2)) \
     ORDER BY seed.slot";

pub(crate) const BINDING_PROJECTIONS_BY_REFERENCE_SQL: &str = "SELECT reference, output_slot, kind FROM resolution_binding_projections \
     WHERE blob_id = ?1 AND reference IN (SELECT value FROM json_each(?2)) \
     ORDER BY reference, output_slot";

pub(crate) const BINDING_PROJECTIONS_BY_OUTPUT_SQL: &str = "SELECT reference, output_slot, kind FROM resolution_binding_projections \
     INDEXED BY resolution_binding_projections_output \
     WHERE blob_id = ?1 AND output_slot IN (SELECT value FROM json_each(?2))";

pub(crate) const QUALIFIED_ROUTES_BY_REFERENCE_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     WHERE blob_id = ?1 AND reference IN (SELECT value FROM json_each(?2)) \
     ORDER BY reference, precedence_ordinal";

pub(crate) const QUALIFIED_ROUTES_BY_QUALIFIER_SLOT_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     INDEXED BY resolution_qualified_routes_slot \
     WHERE blob_id = ?1 AND qualifier_slot IN (SELECT value FROM json_each(?2))";

/// The exact `(qualifier slot, lookup)` pair the interior indexes on, as one
/// two-column JSON array of arrays. Lane CM's rule: a rows reader's key is the
/// in-memory index's exact key, never a prefix of it.
pub(crate) const QUALIFIED_ROUTES_BY_SLOT_LOOKUP_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     INDEXED BY resolution_qualified_routes_slot \
     WHERE blob_id = ?1 AND (qualifier_slot, lookup) IN \
       (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?2)) \
     UNION \
     SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     INDEXED BY resolution_qualified_routes_source_slot \
     WHERE blob_id = ?1 AND source_lookup <> lookup AND (qualifier_slot, source_lookup) IN \
       (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?2))";

/// A route answers under either of its two lookup names.
///
/// This one has no index of its own (owner decision, 2026-09-19): lane SC
/// measured `visit_qualified_route_pages_for_lookups` at zero calls on all
/// five routes, and an index exists only for a statement that is reached. The
/// statement seeks the blob's route prefix on the primary key and tests both
/// lookup columns there, so its work is one blob's routes -- the same bound
/// `visit_qualified_route_inventory_pages` already accepts. When this question
/// gets a measured caller, `(blob_id, lookup)` and `(blob_id, source_lookup)`
/// are the two indexes to add back; they were 3.6 MB on tract.
pub(crate) const QUALIFIED_ROUTES_BY_LOOKUP_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     WHERE blob_id = ?1 \
       AND (lookup IN (SELECT value FROM json_each(?2)) \
            OR source_lookup IN (SELECT value FROM json_each(?2)))";

pub(crate) const QUALIFIED_ROUTES_BY_GAP_REASON_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     INDEXED BY resolution_qualified_routes_gap \
     WHERE blob_id = ?1 AND coarse_gap_reason IN (SELECT value FROM json_each(?2))";

pub(crate) const QUALIFIED_ROUTES_INVENTORY_SQL: &str = "SELECT reference, precedence_ordinal, qualifier_slot, lookup, \
     source_lookup, namespace, projection_output_slot, projection_kind, coarse_gap_reason, open_member_surface FROM resolution_qualified_routes \
     WHERE blob_id = ?1 ORDER BY reference, precedence_ordinal";

pub(crate) const DECLARATION_TYPES_BY_DEFINITION_SQL: &str = "SELECT definition, role, slot FROM resolution_declaration_types \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2)) \
     ORDER BY definition, role, slot";

pub(crate) const DECLARATION_TYPES_BY_SLOT_SQL: &str = "SELECT definition, role, slot FROM resolution_declaration_types \
     INDEXED BY resolution_declaration_types_slot \
     WHERE blob_id = ?1 AND slot IN (SELECT value FROM json_each(?2))";

/// Question 45 keeps the existing view over the source declaration properties
/// (draft section 6), so this reader adds no table: a definition's visibility
/// is already a row keyed exactly as the reader asks.
// Keep the composite requested key together: separate blob equality and a key
// IN list let the canonical view arm scan every declaration in the blob first.
pub(crate) const DECLARATION_VISIBILITIES_BY_DEFINITION_SQL: &str = "SELECT definition_semantic_key, visibility \
     FROM resolution_declaration_visibility_properties \
     WHERE (blob_id, definition_semantic_key) IN (SELECT ?1, value FROM json_each(?2))";

/// Questions 46 and 47 keep the tier 1 table they already have, for the same
/// reason as question 45: it holds the fact under the key the reader holds,
/// and a second copy of it would be the one thing the schema rules forbid.
pub(crate) const MEMBER_SCOPES_BY_DEFINITION_SQL: &str = "SELECT definition_semantic_key, scope_head_node_key \
     FROM resolution_member_scope_properties \
     WHERE blob_id = ?1 AND definition_semantic_key IN (SELECT value FROM json_each(?2))";

pub(crate) const MEMBER_SCOPES_BY_HEAD_SQL: &str = "SELECT definition_semantic_key, scope_head_node_key \
     FROM resolution_member_scope_properties \
     WHERE blob_id = ?1 AND scope_head_node_key IN (SELECT value FROM json_each(?2))";

pub(crate) const MEMBER_OWNERS_BY_DEFINITION_SQL: &str = "SELECT definition_semantic_key, owner_definition_semantic_key, \
     owner_scope_head_node_key, member_kind, member_access, qualifier_compatibility FROM resolution_member_owner_properties \
     WHERE blob_id = ?1 AND definition_semantic_key IN (SELECT value FROM json_each(?2))";

pub(crate) const MEMBER_OWNERS_BY_OWNER_SQL: &str = "SELECT definition_semantic_key, owner_definition_semantic_key, \
     owner_scope_head_node_key, member_kind, member_access, qualifier_compatibility FROM resolution_member_owner_properties \
     INDEXED BY resolution_member_owner_properties_owner \
     WHERE blob_id = ?1 \
       AND owner_definition_semantic_key IN (SELECT value FROM json_each(?2))";

pub(crate) const DEFERRED_MEMBER_OWNERS_BY_DEFINITION_SQL: &str = "SELECT definition, lookup, json(body) FROM resolution_deferred_member_owners \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2)) \
     ORDER BY definition, seq";

pub(crate) const DEFERRED_MEMBER_OWNERS_BY_LOOKUP_SQL: &str = "SELECT definition, lookup, json(body) FROM resolution_deferred_member_owners \
     INDEXED BY resolution_deferred_member_owners_lookup \
     WHERE blob_id = ?1 AND lookup IN (SELECT value FROM json_each(?2))";

pub(crate) const CONSTRUCTION_REQUIREMENTS_BY_DEFINITION_SQL: &str = "SELECT definition, required_owner_definition, kind \
     FROM resolution_construction_requirements \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2)) \
     ORDER BY definition, required_owner_definition, kind";

pub(crate) const SUPERTYPES_BY_DEFINITION_SQL: &str = "SELECT definition, reference, frontier, kind FROM resolution_supertypes \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2)) \
     ORDER BY definition, reference";

pub(crate) const SUPERTYPES_BY_REFERENCE_SQL: &str = "SELECT definition, reference, frontier, kind FROM resolution_supertypes \
     INDEXED BY resolution_supertypes_reference \
     WHERE blob_id = ?1 AND reference IN (SELECT value FROM json_each(?2))";

pub(crate) const SUPERTYPES_BY_FRONTIER_SQL: &str = "SELECT definition, reference, frontier, kind FROM resolution_supertypes \
     INDEXED BY resolution_supertypes_frontier \
     WHERE blob_id = ?1 AND frontier IN (SELECT value FROM json_each(?2))";

pub(crate) const DEFINITION_PROPERTY_GAPS_BY_REASON_SQL: &str = "SELECT definition, kind, frontier, reason, site
     FROM resolution_definition_property_gaps INDEXED BY resolution_definition_property_gaps_provenance
     WHERE blob_id=?1 AND reason IN (SELECT value FROM json_each(?2))";

pub(crate) const DEFINITION_PROPERTY_GAPS_BY_DEFINITION_SQL: &str = "SELECT definition, kind, frontier, reason, site \
     FROM resolution_definition_property_gaps \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2)) \
     ORDER BY definition, seq";

pub(crate) const CALL_OBLIGATIONS_BY_CALLEE_SQL: &str = "SELECT callee_reference, call, receiver_slot, result_slot, \
     explicit_type_argument_count, applicability_reason, json(argument_slots), \
     json(eligible_rules), json(completion), json(type_argument_slots) \
     FROM resolution_call_obligations \
     WHERE blob_id = ?1 AND callee_reference IN (SELECT value FROM json_each(?2))";

pub(crate) const CALL_OBLIGATIONS_BY_REASON_SQL: &str = "SELECT callee_reference, call, receiver_slot, result_slot, \
     explicit_type_argument_count, applicability_reason, json(argument_slots), \
     json(eligible_rules), json(completion), json(type_argument_slots) \
     FROM resolution_call_obligations \
     INDEXED BY resolution_call_obligations_reason \
     WHERE blob_id = ?1 AND applicability_reason IN (SELECT value FROM json_each(?2))";

pub(crate) const TYPE_TRANSFER_OWNER_BY_RULE_SQL: &str =
    "SELECT source_slot,target_slot FROM resolution_type_transfers WHERE blob_id=?1 AND rule=?2";
pub(crate) const CALL_OBLIGATION_OWNER_BY_CALL_SQL: &str =
    "SELECT callee_reference FROM resolution_call_obligations WHERE blob_id=?1 AND call=?2";
pub(crate) const PROPERTY_GAP_OWNER_BY_PROVENANCE_SQL: &str =
    "SELECT definition FROM resolution_definition_property_gaps
     WHERE blob_id=?1 AND reason=?2 AND site=?3 AND kind=?4";

pub(crate) const CALLABLE_PARAMETER_OWNER_BY_DEFINITION_SQL: &str = "SELECT signature_definition FROM resolution_callable_parameter_owners \
     WHERE blob_id=?1 AND parameter_definition=?2";

pub(crate) const CALLABLE_SIGNATURES_BY_DEFINITION_SQL: &str = "SELECT definition, json(body) FROM resolution_callable_signatures \
     WHERE blob_id = ?1 AND definition IN (SELECT value FROM json_each(?2))";

// ---------------------------------------------------------------------------
// What the writer carries from preparation into its transaction
// ---------------------------------------------------------------------------

/// One typed row's JSONB body, with every shared name still a slot.
pub(crate) type PreparedBody = Vec<PathBodyToken>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedTypeFrontierRow {
    pub(crate) slot: i64,
    pub(crate) role: i64,
    pub(crate) identity_reference: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedTypeTransferRow {
    pub(crate) source_slot: i64,
    pub(crate) rule: i64,
    pub(crate) target_slot: i64,
    pub(crate) kind: i64,
    pub(crate) indirection_delta: i64,
    pub(crate) reference_indirection_delta: i64,
    pub(crate) value_transform: i64,
    pub(crate) completion: Option<PreparedBody>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedTypeComponentRow {
    pub(crate) container_slot: i64,
    pub(crate) constructor: i64,
    pub(crate) kind: i64,
    pub(crate) component_slot: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedUnderlyingTypeRow {
    pub(crate) definition: i64,
    pub(crate) slot: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedIntrinsicSeedRow {
    pub(crate) slot: i64,
    pub(crate) kind: i64,
    pub(crate) spelling: String,
    pub(crate) possible_values: PreparedBody,
    pub(crate) completion: Option<PreparedBody>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedIntrinsicSeedIdentityRow {
    pub(crate) identity: u32,
    pub(crate) slot: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedBindingProjectionRow {
    pub(crate) reference: i64,
    pub(crate) output_slot: i64,
    pub(crate) kind: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedQualifiedRouteRow {
    pub(crate) reference: i64,
    pub(crate) precedence_ordinal: i64,
    pub(crate) qualifier_slot: i64,
    pub(crate) lookup: u32,
    pub(crate) source_lookup: u32,
    pub(crate) namespace: i64,
    pub(crate) projection_output_slot: i64,
    pub(crate) projection_kind: i64,
    pub(crate) coarse_gap_reason: i64,
    pub(crate) open_member_surface: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedDeclarationTypeRow {
    pub(crate) definition: i64,
    pub(crate) role: i64,
    pub(crate) slot: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedDeferredMemberOwnerRow {
    pub(crate) definition: i64,
    pub(crate) seq: i64,
    pub(crate) lookup: u32,
    pub(crate) body: PreparedBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedConstructionRequirementRow {
    pub(crate) definition: i64,
    pub(crate) required_owner_definition: i64,
    pub(crate) kind: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedSupertypeRow {
    pub(crate) definition: i64,
    pub(crate) reference: i64,
    pub(crate) frontier: i64,
    pub(crate) kind: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedDefinitionPropertyGapRow {
    pub(crate) definition: i64,
    pub(crate) seq: i64,
    pub(crate) kind: i64,
    pub(crate) frontier: i64,
    pub(crate) reason: i64,
    pub(crate) site: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCallObligationRow {
    pub(crate) callee_reference: i64,
    pub(crate) call: i64,
    pub(crate) receiver_slot: Option<i64>,
    pub(crate) result_slot: i64,
    pub(crate) explicit_type_argument_count: i64,
    pub(crate) applicability_reason: i64,
    pub(crate) argument_slots: PreparedBody,
    pub(crate) type_argument_slots: PreparedBody,
    pub(crate) eligible_rules: PreparedBody,
    pub(crate) completion: Option<PreparedBody>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCallableSignatureRow {
    pub(crate) definition: i64,
    pub(crate) body: PreparedBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCallableParameterOwnerRow {
    pub(crate) parameter_definition: i64,
    pub(crate) signature_definition: i64,
}

/// One blob's typed-fact rows and the shared names they name, in first-use
/// order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PreparedTypedRows {
    pub(crate) shared: Vec<[u8; 32]>,
    pub(crate) type_frontiers: Vec<PreparedTypeFrontierRow>,
    pub(crate) type_transfers: Vec<PreparedTypeTransferRow>,
    pub(crate) type_components: Vec<PreparedTypeComponentRow>,
    pub(crate) underlying_types: Vec<PreparedUnderlyingTypeRow>,
    pub(crate) intrinsic_seeds: Vec<PreparedIntrinsicSeedRow>,
    pub(crate) intrinsic_seed_identities: Vec<PreparedIntrinsicSeedIdentityRow>,
    pub(crate) binding_projections: Vec<PreparedBindingProjectionRow>,
    pub(crate) qualified_routes: Vec<PreparedQualifiedRouteRow>,
    pub(crate) declaration_types: Vec<PreparedDeclarationTypeRow>,
    pub(crate) deferred_member_owners: Vec<PreparedDeferredMemberOwnerRow>,
    pub(crate) construction_requirements: Vec<PreparedConstructionRequirementRow>,
    pub(crate) supertypes: Vec<PreparedSupertypeRow>,
    pub(crate) definition_property_gaps: Vec<PreparedDefinitionPropertyGapRow>,
    pub(crate) call_obligations: Vec<PreparedCallObligationRow>,
    pub(crate) callable_signatures: Vec<PreparedCallableSignatureRow>,
    pub(crate) callable_parameter_owners: Vec<PreparedCallableParameterOwnerRow>,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// One column that always holds a blob-local semantic.
///
/// The assertion is the draft's section 1 invariant made a runtime fact: if a
/// column the reader decodes as local ever held a shared name, the reader
/// would silently answer with the wrong identity, so the writer refuses it at
/// the construction point instead.
fn local(
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
    column: &str,
) -> i64 {
    let identity = identities
        .semantic_identity(semantic)
        .unwrap_or_else(|| panic!("an emitted {column} is in its blob's catalog: {semantic}"));
    assert!(
        identity.shared_name().is_none(),
        "a typed {column} column holds a blob-local semantic, not a shared name: {semantic}"
    );
    keys.semantic(semantic)
}

/// One column that always holds a shared name, as a slot the writer interns.
fn shared(
    names: &mut SharedNames,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
    column: &str,
) -> u32 {
    let identity = identities
        .semantic_identity(semantic)
        .unwrap_or_else(|| panic!("an emitted {column} is in its blob's catalog: {semantic}"));
    let name = identity.shared_name().unwrap_or_else(|| {
        panic!("a typed {column} column holds a shared name, not a blob-local semantic: {semantic}")
    });
    names.slot(identities.shared_name_digest(name))
}

/// One symbol inside a typed body: `>= 0` a blob-local key, `< 0` minus the
/// interned id of a shared name.
fn signed(
    names: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
) -> PathBodyToken {
    let identity = identities
        .semantic_identity(semantic)
        .unwrap_or_else(|| panic!("an emitted semantic is in its blob's catalog: {semantic}"));
    match identity.shared_name() {
        None => PathBodyToken::Int(keys.semantic(semantic)),
        Some(name) => PathBodyToken::Shared(names.slot(identities.shared_name_digest(name))),
    }
}

/// `None` when the row is complete; otherwise its reasons as one JSONB array.
///
/// A reason's semantic travels signed, so the decode needs no identity
/// catalog. A path body writes the same reasons with a bare local key because
/// its decoder already holds the catalog for its symbols; nothing here does.
fn completion_body(
    names: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    completion: &ResolutionCompletion,
) -> Option<PreparedBody> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return None;
    };
    let mut out = Vec::new();
    out.push(PathBodyToken::Open);
    for reason in reasons.iter() {
        out.push(PathBodyToken::Open);
        out.push(PathBodyToken::Int(code(
            ALL_RESOLUTION_COMPLETION_REASON_KINDS,
            reason.kind(),
        )));
        match reason {
            ResolutionIncompleteReason::CyclicExpansion(path) => {
                out.push(PathBodyToken::Int(keys.path(*path)));
            }
            ResolutionIncompleteReason::InconsistentPrecedence(semantic)
            | ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                out.push(signed(names, keys, identities, *semantic));
            }
            ResolutionIncompleteReason::OpenBoundary { semantic, status } => {
                out.push(signed(names, keys, identities, *semantic));
                out.push(PathBodyToken::Int(code(ALL_BOUNDARY_STATUSES, *status)));
            }
            other => panic!("a lowered typed completion cannot carry {other:?}"),
        }
        out.push(PathBodyToken::Close);
    }
    out.push(PathBodyToken::Close);
    Some(out)
}

/// `[[category, identity, indirection, reference_indirection, addressable], ...]`:
/// category 0 a type object, 1 a runtime value; `addressable` is 0 or 1 and is
/// 0 for a type object, which has none.
fn slot_values_body(
    names: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    values: &[ResolutionSlotValue],
) -> PreparedBody {
    let mut out = vec![PathBodyToken::Open];
    for value in values {
        let ty: ResolutionTypeRef = value.ty();
        out.push(PathBodyToken::Open);
        out.push(PathBodyToken::Int(i64::from(value.addressable().is_some())));
        out.push(signed(names, keys, identities, ty.identity()));
        out.push(PathBodyToken::Int(i64::from(ty.indirection())));
        out.push(PathBodyToken::Int(i64::from(ty.reference_indirection())));
        out.push(PathBodyToken::Int(i64::from(
            value.addressable().unwrap_or(false),
        )));
        out.push(PathBodyToken::Close);
    }
    out.push(PathBodyToken::Close);
    out
}

/// Every typed fact of one blob, encoded.
pub(super) fn prepare_typed_rows(
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    typed: &LoweredTypedFragment,
) -> PreparedTypedRows {
    let mut names = SharedNames::default();
    let mut rows = PreparedTypedRows::default();

    for frontier in typed.frontiers() {
        rows.type_frontiers.push(PreparedTypeFrontierRow {
            slot: local(keys, identities, frontier.slot(), "type frontier slot"),
            role: code(ALL_RESOLUTION_TYPE_SLOT_ROLES, frontier.role()),
            identity_reference: frontier.type_identity_reference().map(|(reference, node)| {
                let key = local(
                    keys,
                    identities,
                    reference,
                    "type identity observation reference",
                );
                // Site `n`, its semantic and its node carry one number
                // (`local_identity.rs`, `finish`), so the observing node is the
                // reference's own key and the row does not store it twice.
                assert_eq!(
                    super::resolution_rows::node_key(keys, node),
                    key,
                    "a type identity observation's node is its reference's site number"
                );
                key
            }),
        });
    }

    for transfer in typed.transfers() {
        let rule: &TypeTransferRule = transfer.rule();
        rows.type_transfers.push(PreparedTypeTransferRow {
            source_slot: local(
                keys,
                identities,
                transfer.source_slot(),
                "type transfer source slot",
            ),
            rule: local(keys, identities, rule.semantic(), "type transfer rule"),
            target_slot: local(
                keys,
                identities,
                rule.target_slot(),
                "type transfer target slot",
            ),
            kind: code(ALL_RESOLUTION_TYPE_TRANSFER_KINDS, transfer.kind()),
            indirection_delta: rule.indirection_delta(),
            reference_indirection_delta: rule.reference_indirection_delta(),
            value_transform: value_transform_code(rule.value_transform()),
            completion: completion_body(&mut names, keys, identities, rule.completion()),
        });
    }

    for component in typed.type_components() {
        rows.type_components.push(PreparedTypeComponentRow {
            container_slot: local(
                keys,
                identities,
                component.container(),
                "type component container",
            ),
            constructor: code(
                ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS,
                component.constructor(),
            ),
            kind: code(ALL_RESOLUTION_TYPE_COMPONENT_KINDS, component.kind()),
            component_slot: local(
                keys,
                identities,
                component.component(),
                "type component slot",
            ),
        });
    }

    for underlying in typed.underlying_types() {
        rows.underlying_types.push(PreparedUnderlyingTypeRow {
            definition: local(
                keys,
                identities,
                underlying.definition(),
                "underlying type definition",
            ),
            slot: local(keys, identities, underlying.slot(), "underlying type slot"),
        });
    }

    for seed in typed.intrinsic_seeds() {
        let state: &TypedFrontierState = seed.frontier();
        let slot = local(keys, identities, state.slot(), "intrinsic seed slot");
        if seed.kind()
            != brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind::Structural
        {
            for value in state.possible_values() {
                rows.intrinsic_seed_identities
                    .push(PreparedIntrinsicSeedIdentityRow {
                        identity: shared(
                            &mut names,
                            identities,
                            value.ty().identity(),
                            "intrinsic seed type identity",
                        ),
                        slot,
                    });
            }
        }
        rows.intrinsic_seeds.push(PreparedIntrinsicSeedRow {
            slot,
            kind: code(ALL_INTRINSIC_TYPE_KINDS, seed.kind()),
            spelling: seed.spelling().to_owned(),
            possible_values: slot_values_body(
                &mut names,
                keys,
                identities,
                state.possible_values(),
            ),
            completion: completion_body(&mut names, keys, identities, state.completion()),
        });
    }
    rows.intrinsic_seed_identities
        .sort_unstable_by_key(|row| (row.identity, row.slot));
    rows.intrinsic_seed_identities.dedup();

    for projection in typed.projections() {
        rows.binding_projections.push(PreparedBindingProjectionRow {
            reference: local(
                keys,
                identities,
                projection.reference(),
                "binding projection reference",
            ),
            output_slot: local(
                keys,
                identities,
                projection.output_slot(),
                "binding projection output slot",
            ),
            kind: code(ALL_BINDING_PROJECTION_KINDS, projection.kind()),
        });
    }

    for route in typed.qualified_routes() {
        rows.qualified_routes.push(PreparedQualifiedRouteRow {
            reference: local(
                keys,
                identities,
                route.reference(),
                "qualified route reference",
            ),
            precedence_ordinal: i64::from(route.precedence_ordinal()),
            qualifier_slot: local(
                keys,
                identities,
                route.qualifier_slot(),
                "qualified route qualifier slot",
            ),
            lookup: shared(
                &mut names,
                identities,
                route.lookup(),
                "qualified route lookup",
            ),
            source_lookup: shared(
                &mut names,
                identities,
                route.source_lookup(),
                "qualified route source lookup",
            ),
            namespace: namespace_code(route.namespace()),
            projection_output_slot: local(
                keys,
                identities,
                route.projection_output_slot(),
                "qualified route projection output slot",
            ),
            projection_kind: code(ALL_BINDING_PROJECTION_KINDS, route.projection_kind()),
            coarse_gap_reason: local(
                keys,
                identities,
                route.coarse_gap_reason(),
                "qualified route coarse gap reason",
            ),
            open_member_surface: i64::from(route.open_member_surface()),
        });
    }

    for property in typed.declaration_types() {
        rows.declaration_types.push(PreparedDeclarationTypeRow {
            definition: local(
                keys,
                identities,
                property.definition(),
                "declaration type definition",
            ),
            role: code(ALL_DECLARATION_TYPE_ROLES, property.role()),
            slot: local(keys, identities, property.slot(), "declaration type slot"),
        });
    }

    let mut deferred_sequence = HashMap::default();
    for property in typed.deferred_member_owners() {
        let definition = local(
            keys,
            identities,
            property.definition,
            "deferred member owner definition",
        );
        let seq = next_sequence(&mut deferred_sequence, definition);
        let mut body = vec![PathBodyToken::Open];
        body.push(PathBodyToken::Int(local(
            keys,
            identities,
            property.owner_frontier,
            "deferred member owner frontier",
        )));
        body.push(match property.hierarchy_frontier() {
            None => PathBodyToken::Null,
            Some(frontier) => PathBodyToken::Int(local(
                keys,
                identities,
                frontier,
                "deferred member hierarchy frontier",
            )),
        });
        body.push(PathBodyToken::Int(code(
            ALL_RESOLUTION_MEMBER_KINDS,
            property.kind,
        )));
        body.push(PathBodyToken::Int(code(
            ALL_RESOLUTION_MEMBER_ACCESSES,
            property.access,
        )));
        body.push(PathBodyToken::Int(code(
            ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
            property.qualifier_compatibility,
        )));
        body.push(PathBodyToken::Close);
        rows.deferred_member_owners
            .push(PreparedDeferredMemberOwnerRow {
                definition,
                seq,
                lookup: shared(
                    &mut names,
                    identities,
                    property.lookup,
                    "deferred member owner lookup",
                ),
                body,
            });
    }

    for property in typed.construction_requirements() {
        rows.construction_requirements
            .push(PreparedConstructionRequirementRow {
                definition: local(
                    keys,
                    identities,
                    property.definition(),
                    "construction requirement definition",
                ),
                required_owner_definition: local(
                    keys,
                    identities,
                    property.required_owner_definition(),
                    "construction requirement owner",
                ),
                kind: code(
                    ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
                    property.kind(),
                ),
            });
    }

    for property in typed.supertypes() {
        rows.supertypes.push(PreparedSupertypeRow {
            definition: local(
                keys,
                identities,
                property.definition(),
                "supertype definition",
            ),
            reference: local(
                keys,
                identities,
                property.reference(),
                "supertype reference",
            ),
            frontier: local(keys, identities, property.frontier(), "supertype frontier"),
            kind: code(ALL_RESOLUTION_SUPERTYPE_KINDS, property.kind()),
        });
    }

    let mut gap_sequence = HashMap::default();
    for gap in typed.property_gaps() {
        let definition = local(
            keys,
            identities,
            gap.definition(),
            "property gap definition",
        );
        rows.definition_property_gaps
            .push(PreparedDefinitionPropertyGapRow {
                definition,
                seq: next_sequence(&mut gap_sequence, definition),
                kind: code(ALL_RESOLUTION_GAP_KINDS, gap.kind()),
                frontier: local(keys, identities, gap.frontier(), "property gap frontier"),
                reason: local(
                    keys,
                    identities,
                    gap.reason_semantic(),
                    "property gap reason",
                ),
                site: site_index(gap.source_site()),
            });
    }

    for obligation in typed.call_obligations() {
        let mut argument_slots = vec![PathBodyToken::Open];
        for slot in obligation.argument_slots() {
            argument_slots.push(PathBodyToken::Int(local(
                keys,
                identities,
                *slot,
                "call obligation argument slot",
            )));
        }
        argument_slots.push(PathBodyToken::Close);
        let mut type_argument_slots = vec![PathBodyToken::Open];
        for slots in [
            obligation.type_argument_slots(),
            obligation.owner_type_argument_slots(),
        ] {
            type_argument_slots.push(PathBodyToken::Open);
            for slot in slots {
                type_argument_slots.push(PathBodyToken::Int(local(
                    keys,
                    identities,
                    *slot,
                    "call obligation type argument slot",
                )));
            }
            type_argument_slots.push(PathBodyToken::Close);
        }
        for slot in [
            obligation.expected_result_slot(),
            obligation.owner_type_segment(),
        ] {
            type_argument_slots.push(match slot {
                Some(slot) => PathBodyToken::Int(local(
                    keys,
                    identities,
                    slot,
                    "call obligation expected result or type segment slot",
                )),
                None => PathBodyToken::Null,
            });
        }
        type_argument_slots.push(PathBodyToken::Open);
        for slot in obligation.extra_result_slots() {
            type_argument_slots.push(PathBodyToken::Int(local(
                keys,
                identities,
                *slot,
                "call obligation extra result slot",
            )));
        }
        type_argument_slots.push(PathBodyToken::Close);
        type_argument_slots.push(PathBodyToken::Close);
        let mut eligible_rules = vec![PathBodyToken::Open];
        for rule in obligation.eligible_rules() {
            eligible_rules.push(PathBodyToken::Int(code(
                ALL_RESOLUTION_ENGINE_RULE_KINDS,
                *rule,
            )));
        }
        eligible_rules.push(PathBodyToken::Close);
        rows.call_obligations.push(PreparedCallObligationRow {
            callee_reference: local(
                keys,
                identities,
                obligation.callee_reference(),
                "call obligation callee reference",
            ),
            call: local(keys, identities, obligation.call(), "call obligation call"),
            receiver_slot: obligation
                .receiver_slot()
                .map(|slot| local(keys, identities, slot, "call obligation receiver slot")),
            result_slot: local(
                keys,
                identities,
                obligation.result_slot(),
                "call obligation result slot",
            ),
            explicit_type_argument_count: i64::from(obligation.explicit_type_argument_count()),
            applicability_reason: local(
                keys,
                identities,
                obligation.applicability_reason(),
                "call obligation applicability reason",
            ),
            argument_slots,
            type_argument_slots,
            eligible_rules,
            completion: completion_body(&mut names, keys, identities, obligation.completion()),
        });
    }

    for signature in typed.callable_signatures() {
        let signature_definition = local(
            keys,
            identities,
            signature.definition(),
            "callable signature definition",
        );
        let mut body = vec![PathBodyToken::Open];
        body.push(PathBodyToken::Int(i64::from(
            signature.type_parameter_count(),
        )));
        body.push(PathBodyToken::Open);
        for parameter in signature.parameters() {
            let parameter_definition = local(
                keys,
                identities,
                parameter.definition(),
                "callable parameter definition",
            );
            rows.callable_parameter_owners
                .push(PreparedCallableParameterOwnerRow {
                    parameter_definition,
                    signature_definition,
                });
            body.push(PathBodyToken::Open);
            body.push(PathBodyToken::Int(parameter_definition));
            body.push(PathBodyToken::Int(local(
                keys,
                identities,
                parameter.slot(),
                "callable parameter slot",
            )));
            body.push(PathBodyToken::Int(i64::from(parameter.repeated())));
            body.push(PathBodyToken::Close);
        }
        body.push(PathBodyToken::Close);
        match completion_body(&mut names, keys, identities, signature.completion()) {
            None => body.push(PathBodyToken::Null),
            Some(reasons) => body.extend(reasons),
        }
        body.push(PathBodyToken::Open);
        for binding in signature.result_bindings() {
            body.push(PathBodyToken::Open);
            body.push(PathBodyToken::Int(i64::from(binding.ordinal())));
            body.push(PathBodyToken::Int(binding.indirection_delta()));
            body.push(PathBodyToken::Int(binding.reference_indirection_delta()));
            body.push(PathBodyToken::Close);
        }
        body.push(PathBodyToken::Close);
        body.push(match signature.receiver() {
            Some(form) => PathBodyToken::Int(code(ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS, form)),
            None => PathBodyToken::Null,
        });
        for parameter in [
            signature.result_type_parameter(),
            signature.result_owner_type_parameter(),
        ] {
            match parameter {
                Some(parameter) => {
                    body.push(PathBodyToken::Open);
                    body.push(PathBodyToken::Int(i64::from(parameter.ordinal())));
                    body.push(PathBodyToken::Int(parameter.indirection_delta()));
                    body.push(PathBodyToken::Int(parameter.reference_indirection_delta()));
                    body.push(PathBodyToken::Close);
                }
                None => body.push(PathBodyToken::Null),
            }
        }
        body.push(PathBodyToken::Open);
        for result in signature.result_types() {
            body.push(PathBodyToken::Open);
            body.push(PathBodyToken::Int(i64::from(result.ordinal())));
            body.push(PathBodyToken::Int(local(
                keys,
                identities,
                result.slot(),
                "callable result type slot",
            )));
            body.push(PathBodyToken::Close);
        }
        body.push(PathBodyToken::Close);
        body.push(PathBodyToken::Close);
        rows.callable_signatures.push(PreparedCallableSignatureRow {
            definition: signature_definition,
            body,
        });
    }

    rows.shared = names.into_digests();
    rows
}

/// The next ordinal of one parent key, so that a child family keyed
/// `(parent, seq)` keeps the lowering's order without a second sort.
fn next_sequence(counters: &mut HashMap<i64, i64>, parent: i64) -> i64 {
    let next = counters.entry(parent).or_insert(0);
    let sequence = *next;
    *next += 1;
    sequence
}

fn site_index(site: ResolutionSiteId) -> i64 {
    i64::try_from(site.index()).expect("a site ordinal fits SQLite INTEGER")
}

pub(crate) fn value_transform_code(transform: TypeTransferValueTransform) -> i64 {
    match transform {
        TypeTransferValueTransform::Preserve => 0,
        TypeTransferValueTransform::ToRuntime { addressable: false } => 1,
        TypeTransferValueTransform::ToRuntime { addressable: true } => 2,
        TypeTransferValueTransform::ToNoValue => 3,
        TypeTransferValueTransform::TypeObjectOnly => 4,
        TypeTransferValueTransform::AddressableRuntimeOnly => 5,
        TypeTransferValueTransform::AddressableOperandOnly => 6,
        TypeTransferValueTransform::RuntimeOnly => 7,
    }
}

pub(crate) fn value_transform_from_code(value: i64) -> TypeTransferValueTransform {
    match value {
        0 => TypeTransferValueTransform::Preserve,
        1 => TypeTransferValueTransform::ToRuntime { addressable: false },
        2 => TypeTransferValueTransform::ToRuntime { addressable: true },
        3 => TypeTransferValueTransform::ToNoValue,
        4 => TypeTransferValueTransform::TypeObjectOnly,
        5 => TypeTransferValueTransform::AddressableRuntimeOnly,
        6 => TypeTransferValueTransform::AddressableOperandOnly,
        7 => TypeTransferValueTransform::RuntimeOnly,
        other => {
            panic!("stored type transfer value transform code {other} is outside its vocabulary")
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// What a typed row's integers mean in one mounted blob.
///
/// It is two numbers, not a page: the mount ordinal that every local key is
/// spliced with, and the fragment each decoded row is owned by. A typed read
/// therefore opens no interior.
#[derive(Clone, Copy)]
pub(crate) struct TypedRowContext<'names> {
    pub(crate) fragment: BindingFragmentId,
    pub(crate) ordinal: u32,
    pub(crate) names: &'names dyn SharedNameInterner,
}

impl TypedRowContext<'_> {
    pub(crate) fn semantic(self, key: i64) -> SemanticId {
        SemanticId::local(
            self.ordinal,
            u32::try_from(key).expect("a stored typed local key is nonnegative and fits u32"),
        )
    }

    /// One signed symbol out of a typed body.
    fn signed_semantic(self, value: i64) -> SemanticId {
        if value < 0 {
            return SemanticId::shared_name(
                self.names.from_persisted(SharedNameId::interned(-value)),
            );
        }
        self.semantic(value)
    }

    pub(crate) fn node(self, key: i64) -> crate::analyzer::resolution::BindingNodeId {
        crate::analyzer::resolution::BindingNodeId::local(
            self.ordinal,
            u32::try_from(key).expect("a stored typed node key is nonnegative and fits u32"),
        )
    }

    fn path(self, key: i64) -> PartialPathId {
        PartialPathId::local(
            self.ordinal,
            u32::try_from(key).expect("a stored typed path key is nonnegative and fits u32"),
        )
    }
}

/// The substantial typed body structure is shared; integer identity and
/// completion authority remain explicit at each durable/stage boundary.
pub(crate) trait TypedBodyDecoder: Copy {
    fn semantic(self, cell: i64) -> SemanticId;
    fn signed_semantic(self, cell: i64) -> SemanticId;
    fn completion(self, body: Option<&str>) -> ResolutionCompletion;
}

impl TypedBodyDecoder for TypedRowContext<'_> {
    fn semantic(self, cell: i64) -> SemanticId {
        self.semantic(cell)
    }
    fn signed_semantic(self, cell: i64) -> SemanticId {
        self.signed_semantic(cell)
    }
    fn completion(self, body: Option<&str>) -> ResolutionCompletion {
        decode_completion(self, body)
    }
}

type Element = serde_json::Value;

fn array<'value>(value: &'value Element, what: &str) -> &'value [Element] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("a stored typed row's {what} is an array, got {value}"))
}

fn integer(value: &Element, what: &str) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("a stored typed row's {what} is an integer, got {value}"))
}

/// One stored JSONB body, parsed once.
pub(crate) fn parse_body(body: &str) -> Element {
    serde_json::from_str(body).expect("a stored typed body is the JSON this module wrote")
}

/// `NULL` is complete; anything else is the reason array.
pub(crate) fn decode_completion(
    context: TypedRowContext,
    body: Option<&str>,
) -> ResolutionCompletion {
    let Some(body) = body else {
        return ResolutionCompletion::Complete;
    };
    let parsed = parse_body(body);
    let mut reasons = Vec::new();
    for reason in array(&parsed, "completion") {
        let cells = array(reason, "completion reason");
        let kind = from_code(
            ALL_RESOLUTION_COMPLETION_REASON_KINDS,
            integer(&cells[0], "completion reason kind"),
            "completion reason kind",
        );
        reasons.push(match kind {
            brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind::CyclicExpansion => {
                ResolutionIncompleteReason::CyclicExpansion(
                    context.path(integer(&cells[1], "cyclic expansion path")),
                )
            }
            brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind::InconsistentPrecedence => {
                ResolutionIncompleteReason::InconsistentPrecedence(
                    context.signed_semantic(integer(&cells[1], "inconsistent precedence semantic")),
                )
            }
            brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind::UnsupportedSemantic => {
                ResolutionIncompleteReason::UnsupportedSemantic(
                    context.signed_semantic(integer(&cells[1], "unsupported semantic")),
                )
            }
            brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind::OpenBoundary => {
                ResolutionIncompleteReason::OpenBoundary {
                    semantic: context
                        .signed_semantic(integer(&cells[1], "open boundary semantic")),
                    status: from_code(
                        ALL_BOUNDARY_STATUSES,
                        integer(&cells[2], "open boundary status"),
                        "boundary status",
                    ),
                }
            }
        });
    }
    ResolutionCompletion::incomplete(reasons)
}

pub(crate) fn decode_type_frontier(
    context: TypedRowContext,
    slot: i64,
    role: i64,
    identity_reference: Option<i64>,
) -> LoweredTypedFrontier {
    let frontier = LoweredTypedFrontier::new(
        context.semantic(slot),
        from_code(ALL_RESOLUTION_TYPE_SLOT_ROLES, role, "type slot role"),
    );
    match identity_reference {
        None => frontier,
        Some(reference) => frontier
            .with_type_identity_reference(context.semantic(reference), context.node(reference)),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_type_transfer(
    context: TypedRowContext,
    source_slot: i64,
    rule: i64,
    target_slot: i64,
    kind: i64,
    indirection_delta: i64,
    reference_indirection_delta: i64,
    value_transform: i64,
    completion: Option<&str>,
) -> LoweredTypeTransfer {
    LoweredTypeTransfer::new(
        context.semantic(source_slot),
        from_code(
            ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
            kind,
            "type transfer kind",
        ),
        TypeTransferRule::new_with_reference_indirection(
            context.semantic(rule),
            context.semantic(target_slot),
            indirection_delta,
            reference_indirection_delta,
            value_transform_from_code(value_transform),
            decode_completion(context, completion),
        ),
    )
}

pub(crate) fn decode_type_component(
    context: TypedRowContext,
    container: i64,
    constructor: i64,
    kind: i64,
    component: i64,
) -> LoweredTypeComponent {
    LoweredTypeComponent::new(
        context.semantic(container),
        from_code(
            ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS,
            constructor,
            "type component constructor",
        ),
        from_code(
            ALL_RESOLUTION_TYPE_COMPONENT_KINDS,
            kind,
            "type component kind",
        ),
        context.semantic(component),
    )
}

pub(crate) fn decode_underlying_type(
    context: TypedRowContext,
    definition: i64,
    slot: i64,
) -> LoweredUnderlyingType {
    LoweredUnderlyingType::new(context.semantic(definition), context.semantic(slot))
}

pub(crate) fn decode_intrinsic_seed(
    context: TypedRowContext,
    slot: i64,
    kind: i64,
    spelling: &str,
    possible_values: &str,
    completion: Option<&str>,
) -> LoweredIntrinsicSeed {
    let values = decode_intrinsic_values(context, possible_values);
    LoweredIntrinsicSeed::new(
        from_code(ALL_INTRINSIC_TYPE_KINDS, kind, "intrinsic type kind"),
        spelling,
        TypedFrontierState::new(
            context.semantic(slot),
            values,
            decode_completion(context, completion),
        ),
    )
}

pub(crate) fn decode_intrinsic_values(
    context: impl TypedBodyDecoder,
    possible_values: &str,
) -> Vec<ResolutionSlotValue> {
    let parsed = parse_body(possible_values);
    let mut values = Vec::new();
    for value in array(&parsed, "intrinsic seed value") {
        let cells = array(value, "intrinsic seed value");
        let ty = ResolutionTypeRef::new_with_reference_indirection(
            context.signed_semantic(integer(&cells[1], "intrinsic seed type identity")),
            u32::try_from(integer(&cells[2], "intrinsic seed indirection"))
                .expect("a stored indirection fits u32"),
            u32::try_from(integer(&cells[3], "intrinsic seed reference indirection"))
                .expect("a stored reference indirection fits u32"),
        );
        values.push(if integer(&cells[0], "intrinsic seed category") == 0 {
            ResolutionSlotValue::type_object(ty)
        } else {
            ResolutionSlotValue::runtime(
                ty,
                integer(&cells[4], "intrinsic seed addressability") != 0,
            )
        });
    }
    values
}

pub(crate) fn decode_binding_projection(
    context: TypedRowContext,
    reference: i64,
    output_slot: i64,
    kind: i64,
) -> LoweredBindingProjection {
    LoweredBindingProjection::new(
        context.semantic(reference),
        context.semantic(output_slot),
        from_code(
            ALL_BINDING_PROJECTION_KINDS,
            kind,
            "binding projection kind",
        ),
    )
}

/// The nine route columns, in the order [`QUALIFIED_ROUTE_COLUMNS`] names them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_qualified_route(
    context: TypedRowContext,
    reference: i64,
    precedence_ordinal: i64,
    qualifier_slot: i64,
    lookup: i64,
    source_lookup: i64,
    namespace: i64,
    projection_output_slot: i64,
    projection_kind: i64,
    coarse_gap_reason: i64,
    open_member_surface: i64,
) -> LoweredQualifiedSeededRoute {
    LoweredQualifiedSeededRoute::new_with_source_lookup(
        context.semantic(reference),
        context.semantic(qualifier_slot),
        SemanticId::shared_name(context.names.from_persisted(SharedNameId::interned(lookup))),
        from_code(
            brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_NAMESPACES,
            namespace,
            "resolution namespace",
        ),
        SemanticId::shared_name(
            context
                .names
                .from_persisted(SharedNameId::interned(source_lookup)),
        ),
        u32::try_from(precedence_ordinal).expect("a stored precedence ordinal fits u32"),
        context.semantic(projection_output_slot),
        from_code(
            ALL_BINDING_PROJECTION_KINDS,
            projection_kind,
            "binding projection kind",
        ),
        context.semantic(coarse_gap_reason),
        open_member_surface != 0,
    )
}

pub(crate) fn decode_declaration_type(
    context: TypedRowContext,
    definition: i64,
    role: i64,
    slot: i64,
) -> LoweredDeclarationTypeProperty {
    LoweredDeclarationTypeProperty::new(
        context.semantic(definition),
        context.semantic(slot),
        from_code(ALL_DECLARATION_TYPE_ROLES, role, "declaration type role"),
    )
}

pub(crate) fn decode_deferred_member_owner(
    context: TypedRowContext,
    definition: i64,
    lookup: i64,
    body: &str,
) -> LoweredDeferredMemberOwner {
    decode_deferred_owner_body(
        context,
        context.semantic(definition),
        SemanticId::shared_name(context.names.from_persisted(SharedNameId::interned(lookup))),
        body,
    )
}

pub(crate) fn decode_deferred_owner_body(
    context: impl TypedBodyDecoder,
    definition: SemanticId,
    lookup: SemanticId,
    body: &str,
) -> LoweredDeferredMemberOwner {
    let parsed = parse_body(body);
    let cells = array(&parsed, "deferred member owner body");
    let owner = LoweredDeferredMemberOwner::new(
        definition,
        context.semantic(integer(&cells[0], "deferred member owner frontier")),
        lookup,
        from_code(
            ALL_RESOLUTION_MEMBER_KINDS,
            integer(&cells[2], "member kind"),
            "member kind",
        ),
        from_code(
            ALL_RESOLUTION_MEMBER_ACCESSES,
            integer(&cells[3], "member access"),
            "member access",
        ),
        from_code(
            ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
            integer(&cells[4], "member qualifier compatibility"),
            "member qualifier compatibility",
        ),
    );
    if cells[1].is_null() {
        owner
    } else {
        owner.with_hierarchy_frontier(Some(
            context.semantic(integer(&cells[1], "deferred member hierarchy frontier")),
        ))
    }
}

pub(crate) fn decode_construction_requirement(
    context: TypedRowContext,
    definition: i64,
    required_owner_definition: i64,
    kind: i64,
) -> LoweredConstructionRequirementProperty {
    LoweredConstructionRequirementProperty::new(
        context.semantic(definition),
        context.semantic(required_owner_definition),
        from_code(
            ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
            kind,
            "construction requirement kind",
        ),
    )
}

pub(crate) fn decode_supertype(
    context: TypedRowContext,
    definition: i64,
    reference: i64,
    frontier: i64,
    kind: i64,
) -> LoweredSupertypeProperty {
    LoweredSupertypeProperty::new(
        context.semantic(definition),
        context.semantic(reference),
        context.semantic(frontier),
        from_code(ALL_RESOLUTION_SUPERTYPE_KINDS, kind, "supertype kind"),
    )
}

pub(crate) fn decode_definition_property_gap(
    context: TypedRowContext,
    definition: i64,
    kind: i64,
    frontier: i64,
    reason: i64,
    site: i64,
) -> LoweredDefinitionPropertyGap {
    LoweredDefinitionPropertyGap::new(
        context.semantic(definition),
        ResolutionSiteId::try_from_index(
            usize::try_from(site).expect("a stored site ordinal is nonnegative"),
        )
        .expect("a stored site ordinal fits its id"),
        from_code(ALL_RESOLUTION_GAP_KINDS, kind, "gap kind"),
        context.semantic(frontier),
        context.semantic(reason),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_call_obligation(
    context: TypedRowContext,
    callee_reference: i64,
    call: i64,
    receiver_slot: Option<i64>,
    result_slot: i64,
    explicit_type_argument_count: i64,
    applicability_reason: i64,
    argument_slots: &str,
    type_argument_slots: &str,
    eligible_rules: &str,
    completion: Option<&str>,
) -> LoweredCallApplicabilityObligation {
    let parsed_arguments = parse_body(argument_slots);
    let arguments = array(&parsed_arguments, "call obligation argument slots")
        .iter()
        .map(|slot| context.semantic(integer(slot, "call obligation argument slot")))
        .collect::<Vec<_>>();
    let parsed_type_arguments = parse_body(type_argument_slots);
    let type_argument_cells = array(
        &parsed_type_arguments,
        "call obligation type argument slots",
    );
    assert!(
        (4..=5).contains(&type_argument_cells.len()),
        "call obligation type argument body has legacy or result-extended shape"
    );
    let [own, owner, expected, segment] = [0, 1, 2, 3].map(|cell| &type_argument_cells[cell]);
    let slots = |cell| {
        array(cell, "call obligation type argument slots")
            .iter()
            .map(|slot| context.semantic(integer(slot, "call obligation type argument slot")))
            .collect::<Vec<_>>()
    };
    let (type_arguments, owner_type_arguments) = (slots(own), slots(owner));
    let extra_result_slots = type_argument_cells.get(4).map(slots).unwrap_or_default();
    let [expected, segment] = [expected, segment].map(|cell| {
        (!cell.is_null()).then(|| {
            context.semantic(integer(
                cell,
                "call obligation expected result or type segment slot",
            ))
        })
    });
    let parsed_rules = parse_body(eligible_rules);
    let rules = array(&parsed_rules, "call obligation eligible rules")
        .iter()
        .map(|rule| {
            from_code(
                ALL_RESOLUTION_ENGINE_RULE_KINDS,
                integer(rule, "engine rule kind"),
                "engine rule kind",
            )
        })
        .collect::<Vec<ResolutionEngineRuleKind>>();
    LoweredCallApplicabilityObligation::new(
        context.semantic(call),
        context.semantic(callee_reference),
        receiver_slot.map(|slot| context.semantic(slot)),
        context.semantic(result_slot),
        arguments,
        rules,
        u32::try_from(explicit_type_argument_count).expect("a stored type argument count fits u32"),
        context.semantic(applicability_reason),
        decode_completion(context, completion),
    )
    .with_extra_result_slots(extra_result_slots)
    .with_type_argument_slots(type_arguments)
    .with_owner_type_arguments(segment, owner_type_arguments)
    .with_expected_result_slot(expected)
}

pub(crate) fn decode_callable_signature(
    context: TypedRowContext,
    definition: i64,
    body: &str,
) -> LoweredCallableSignatureProperty {
    decode_callable_signature_body(context, context.semantic(definition), body)
}

pub(crate) fn decode_callable_signature_body(
    context: impl TypedBodyDecoder,
    definition: SemanticId,
    body: &str,
) -> LoweredCallableSignatureProperty {
    let parsed = parse_body(body);
    let cells = array(&parsed, "callable signature body");
    assert!(
        (7..=8).contains(&cells.len()),
        "callable signature body has legacy or result-extended shape"
    );
    let parameters = array(&cells[1], "callable signature parameters")
        .iter()
        .enumerate()
        .map(|(ordinal, parameter)| {
            let parameter = array(parameter, "callable parameter");
            LoweredCallableParameterProperty::new(
                u32::try_from(ordinal).expect("a parameter ordinal fits u32"),
                context.semantic(integer(&parameter[0], "callable parameter definition")),
                context.semantic(integer(&parameter[1], "callable parameter slot")),
                integer(&parameter[2], "callable parameter repetition") != 0,
            )
        })
        .collect::<Vec<_>>();
    let completion = if cells[2].is_null() {
        ResolutionCompletion::Complete
    } else {
        context.completion(Some(&cells[2].to_string()))
    };
    let result_bindings = array(&cells[3], "callable result bindings")
        .iter()
        .map(|binding| {
            let binding = array(binding, "callable result binding");
            LoweredCallableResultBinding::new(
                u32::try_from(integer(&binding[0], "callable result binding ordinal"))
                    .expect("a stored result binding ordinal fits u32"),
                integer(&binding[1], "callable result binding indirection delta"),
                integer(
                    &binding[2],
                    "callable result binding reference indirection delta",
                ),
            )
        })
        .collect::<Vec<_>>();
    let [result_type_parameter, result_owner_type_parameter] = [5, 6].map(|cell| {
        (!cells[cell].is_null()).then(|| {
            let parameter = array(&cells[cell], "callable result type parameter");
            LoweredCallableResultBinding::new(
                u32::try_from(integer(
                    &parameter[0],
                    "callable result type parameter position",
                ))
                .expect("a stored type parameter position fits u32"),
                integer(&parameter[1], "callable result type parameter indirection"),
                integer(
                    &parameter[2],
                    "callable result type parameter reference indirection",
                ),
            )
        })
    });
    let receiver = (!cells[4].is_null()).then(|| {
        from_code(
            ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS,
            integer(&cells[4], "callable receiver form"),
            "callable receiver form",
        )
    });
    let result_types = cells
        .get(7)
        .map(|cell| {
            array(cell, "callable result types")
                .iter()
                .map(|result| {
                    let result = array(result, "callable result type");
                    LoweredCallableResultTypeProperty::new(
                        u32::try_from(integer(&result[0], "callable result type ordinal"))
                            .expect("a stored result type ordinal fits u32"),
                        context.semantic(integer(&result[1], "callable result type slot")),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    LoweredCallableSignatureProperty::new(
        definition,
        u32::try_from(integer(&cells[0], "callable type parameter count"))
            .expect("a stored type parameter count fits u32"),
        parameters,
        completion,
    )
    .with_result_types(result_types)
    .with_result_bindings(result_bindings)
    .with_receiver(receiver)
    .with_result_type_parameter(result_type_parameter)
    .with_result_owner_type_parameter(result_owner_type_parameter)
}

/// The Rust-side mapping for the member vocabularies the reused tier 1 tables
/// still spell as text. Those tables belong to the structural lane's own text
/// decision, so this block reads their labels rather than rewriting them.
pub(crate) fn member_kind_from_label(label: &str) -> ResolutionMemberKind {
    ResolutionMemberKind::from_label(label)
        .unwrap_or_else(|| panic!("stored member kind {label:?} is outside its vocabulary"))
}

pub(crate) fn member_access_from_label(label: &str) -> ResolutionMemberAccess {
    ResolutionMemberAccess::from_label(label)
        .unwrap_or_else(|| panic!("stored member access {label:?} is outside its vocabulary"))
}

pub(crate) fn member_qualifier_compatibility_from_label(
    label: &str,
) -> ResolutionMemberQualifierCompatibility {
    ResolutionMemberQualifierCompatibility::from_label(label).unwrap_or_else(|| {
        panic!("stored member qualifier compatibility {label:?} is outside its vocabulary")
    })
}

/// Declared frontiers and effective lexical frontier gaps are separate authority.
/// A qualified route owns its own coarse reason, so that reason does not leak
/// into the frontier completion. A missing frontier with no gap yields no row.
pub(crate) const FRONTIER_COMPLETION_SQL: &str = "WITH requested AS (SELECT value AS slot FROM json_each(?2)), effective AS (SELECT g.subject, g.reason FROM requested k JOIN resolution_gaps g ON g.blob_id=?1 AND g.covers=7 AND g.subject=k.slot JOIN resolution_gap_reasons r ON r.blob_id=g.blob_id AND r.reason=g.reason WHERE NOT(r.origin=?3 AND EXISTS(SELECT 1 FROM resolution_qualified_routes q WHERE q.blob_id=g.blob_id AND q.coarse_gap_reason=g.reason))), declared AS (SELECT f.slot FROM requested k JOIN resolution_type_frontiers f ON f.blob_id=?1 AND f.slot=k.slot UNION SELECT subject FROM effective) SELECT d.slot, json_group_array(DISTINCT e.reason) FILTER(WHERE e.reason IS NOT NULL) FROM declared d LEFT JOIN effective e ON e.subject=d.slot GROUP BY d.slot ORDER BY d.slot";
pub(crate) const GAP_REASON_PROVENANCE_SQL: &str = "SELECT reason, site, origin FROM resolution_gap_reasons WHERE blob_id=?1 AND reason IN (SELECT value FROM json_each(?2)) ORDER BY reason";

pub(crate) fn frontier_completion_sql() -> String {
    FRONTIER_COMPLETION_SQL.replace(
        "?3",
        &super::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference,
        )
        .to_string(),
    )
}
