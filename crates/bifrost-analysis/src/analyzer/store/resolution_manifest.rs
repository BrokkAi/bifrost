//! Canonical producer identity for complete durable resolution body families.

use super::resolution_prepare::{resolution_rows::*, typed_rows::*};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

pub(super) const BODY_MANIFEST_COLUMNS: &[&str] = &[
    "expected_path_body_count",
    "expected_site_body_count",
    "expected_gap_body_count",
    "expected_gap_reason_count",
    "expected_type_frontier_count",
    "expected_type_transfer_count",
    "expected_type_component_count",
    "expected_underlying_type_count",
    "expected_intrinsic_seed_count",
    "expected_intrinsic_seed_identity_count",
    "expected_binding_projection_count",
    "expected_qualified_route_count",
    "expected_declaration_type_count",
    "expected_deferred_member_owner_count",
    "expected_construction_requirement_count",
    "expected_supertype_count",
    "expected_definition_property_gap_count",
    "expected_call_obligation_count",
    "expected_callable_signature_count",
    "expected_callable_parameter_owner_count",
    "expected_capsule_input_count",
    "expected_capsule_declaration_count",
    "expected_capsule_reference_context_count",
];

trait CanonicalCell {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Option<()>;
}
impl CanonicalCell for i64 {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        _: &[[u8; 32]],
        _: &CancellationToken,
    ) -> Option<()> {
        hash.field("integer", &self.to_be_bytes());
        Some(())
    }
}
impl CanonicalCell for u8 {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        _: &[[u8; 32]],
        _: &CancellationToken,
    ) -> Option<()> {
        hash.field("byte", &[*self]);
        Some(())
    }
}
impl CanonicalCell for bool {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        _: &[[u8; 32]],
        _: &CancellationToken,
    ) -> Option<()> {
        hash.field("boolean", &[u8::from(*self)]);
        Some(())
    }
}
impl CanonicalCell for u32 {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        _: &CancellationToken,
    ) -> Option<()> {
        hash.field("shared_digest", &shared[*self as usize]);
        Some(())
    }
}
impl CanonicalCell for String {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        _: &[[u8; 32]],
        _: &CancellationToken,
    ) -> Option<()> {
        hash.field("text", self.as_bytes());
        Some(())
    }
}
impl<T: CanonicalCell> CanonicalCell for Option<T> {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Option<()> {
        match self {
            Some(value) => {
                hash.field("option", b"some");
                value.hash(hash, shared, cancellation)?;
            }
            None => hash.field("option", b"none"),
        }
        Some(())
    }
}
impl CanonicalCell for PathBodyToken {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Option<()> {
        match self {
            Self::Open => hash.field("token", b"open"),
            Self::Close => hash.field("token", b"close"),
            Self::Null => hash.field("token", b"null"),
            Self::Int(value) => value.hash(hash, shared, cancellation)?,
            Self::Shared(slot) => slot.hash(hash, shared, cancellation)?,
        }
        Some(())
    }
}
impl<T: CanonicalCell> CanonicalCell for Vec<T> {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Option<()> {
        hash.field("length", &(self.len() as u64).to_be_bytes());
        for value in self {
            if cancellation.is_cancelled() {
                return None;
            }
            value.hash(hash, shared, cancellation)?;
        }
        Some(())
    }
}
impl CanonicalCell for (PathBodyToken, bool) {
    fn hash(
        &self,
        hash: &mut CanonicalHasher,
        shared: &[[u8; 32]],
        cancellation: &CancellationToken,
    ) -> Option<()> {
        self.0.hash(hash, shared, cancellation)?;
        self.1.hash(hash, shared, cancellation)
    }
}

macro_rules! canonical_row {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl CanonicalCell for $ty {
            fn hash(&self, hash: &mut CanonicalHasher, shared: &[[u8; 32]], cancellation: &CancellationToken) -> Option<()> {
                $(hash.field("column", stringify!($field).as_bytes());
                  self.$field.hash(hash, shared, cancellation)?;)+
                Some(())
            }
        }
    };
}
canonical_row!(PreparedRootEndpoint, symbols, open_tail);
canonical_row!(
    PreparedPathRow,
    path,
    start_node,
    start_lead_local,
    start_lead_shared,
    start_lead_scoped,
    end_node,
    end_lead_local,
    end_lead_shared,
    end_lead_scoped,
    root_terminal,
    root_endpoint,
    body
);
canonical_row!(
    PreparedSiteRow,
    site,
    role,
    namespace,
    site_kind,
    start_byte,
    end_byte,
    unqualified,
    owner,
    receiver_origin,
    go_spelling_namespace,
    go_definition_namespaces,
    go_package_qualifier
);
canonical_row!(PreparedGapRow, covers, subject, lookup, gap, reason);
canonical_row!(PreparedGapReasonRow, reason, site, origin);
canonical_row!(PreparedTypeFrontierRow, slot, role, identity_reference);
canonical_row!(
    PreparedTypeTransferRow,
    source_slot,
    rule,
    target_slot,
    kind,
    indirection_delta,
    reference_indirection_delta,
    value_transform,
    completion
);
canonical_row!(
    PreparedTypeComponentRow,
    container_slot,
    constructor,
    kind,
    component_slot
);
canonical_row!(PreparedUnderlyingTypeRow, definition, slot);
canonical_row!(
    PreparedIntrinsicSeedRow,
    slot,
    kind,
    spelling,
    possible_values,
    completion
);
canonical_row!(PreparedIntrinsicSeedIdentityRow, identity, slot);
canonical_row!(PreparedBindingProjectionRow, reference, output_slot, kind);
canonical_row!(
    PreparedQualifiedRouteRow,
    reference,
    precedence_ordinal,
    qualifier_slot,
    lookup,
    source_lookup,
    namespace,
    projection_output_slot,
    projection_kind,
    coarse_gap_reason
);
canonical_row!(PreparedDeclarationTypeRow, definition, role, slot);
canonical_row!(
    PreparedDeferredMemberOwnerRow,
    definition,
    seq,
    lookup,
    body
);
canonical_row!(
    PreparedConstructionRequirementRow,
    definition,
    required_owner_definition,
    kind
);
canonical_row!(PreparedSupertypeRow, definition, reference, frontier, kind);
canonical_row!(
    PreparedDefinitionPropertyGapRow,
    definition,
    seq,
    kind,
    frontier,
    reason,
    site
);
canonical_row!(
    PreparedCallObligationRow,
    callee_reference,
    call,
    receiver_slot,
    result_slot,
    explicit_type_argument_count,
    applicability_reason,
    argument_slots,
    type_argument_slots,
    eligible_rules,
    completion
);
canonical_row!(PreparedCallableSignatureRow, definition, body);
canonical_row!(
    PreparedCallableParameterOwnerRow,
    parameter_definition,
    signature_definition
);

fn family<T: CanonicalCell>(
    hash: &mut CanonicalHasher,
    name: &str,
    rows: &[T],
    shared: &[[u8; 32]],
    cancellation: &CancellationToken,
) -> Option<()> {
    let mut digests = Vec::with_capacity(rows.len());
    for row in rows {
        if cancellation.is_cancelled() {
            return None;
        }
        let mut row_hash = CanonicalHasher::new(b"bifrost-resolution-body-row:v1");
        row.hash(&mut row_hash, shared, cancellation)?;
        digests.push(row_hash.finish());
    }
    // Canonical order follows the complete producer row, not first-use interning.
    let digests = super::resolution::cancellable_sort_by(digests, Ord::cmp, cancellation)?;
    hash.field("family", name.as_bytes());
    hash.field("row_count", &(digests.len() as u64).to_be_bytes());
    for digest in digests {
        if cancellation.is_cancelled() {
            return None;
        }
        hash.field("row", &digest);
    }
    Some(())
}

// Keep the content families separate so the digest binds each one.
#[allow(clippy::too_many_arguments)]
pub(super) fn complete_body_digest(
    headers: [u8; 32],
    paths: &PreparedPathRows,
    sites: &[PreparedSiteRow],
    typed: &PreparedTypedRows,
    gaps: &PreparedGapRows,
    recipes: &[PreparedLookupRecipeRow],
    membership: &[[u8; 32]],
    cancellation: &CancellationToken,
) -> Option<[u8; 32]> {
    let mut hash = CanonicalHasher::new(b"bifrost-complete-resolution-content:v1");
    hash.field("headers", &headers);
    family(&mut hash, "paths", &paths.rows, &paths.shared, cancellation)?;
    family(&mut hash, "sites", sites, &[], cancellation)?;
    family(&mut hash, "gaps", &gaps.rows, &gaps.shared, cancellation)?;
    family(&mut hash, "gap_reasons", &gaps.reasons, &[], cancellation)?;
    macro_rules! typed_family { ($($name:ident),+ $(,)?) => {$({
        family(&mut hash, stringify!($name), &typed.$name, &typed.shared, cancellation)?;
    })+}; }
    typed_family!(
        type_frontiers,
        type_transfers,
        type_components,
        underlying_types,
        intrinsic_seeds,
        intrinsic_seed_identities,
        binding_projections,
        qualified_routes,
        declaration_types,
        deferred_member_owners,
        construction_requirements,
        supertypes,
        definition_property_gaps,
        call_obligations,
        callable_signatures,
        callable_parameter_owners
    );
    let members =
        super::resolution::cancellable_sort_by(membership.to_vec(), Ord::cmp, cancellation)?;
    hash.field("membership_count", &(members.len() as u64).to_be_bytes());
    for digest in members {
        if cancellation.is_cancelled() {
            return None;
        }
        hash.field("member", &digest);
    }
    let recipes = super::resolution::cancellable_sort_by(
        recipes.iter().collect::<Vec<_>>(),
        |left, right| left.identity_digest.cmp(&right.identity_digest),
        cancellation,
    )?;
    hash.field("recipe_count", &(recipes.len() as u64).to_be_bytes());
    for recipe in recipes {
        if cancellation.is_cancelled() {
            return None;
        }
        hash.field("recipe_identity", &recipe.identity_digest);
        hash.field("recipe_language", &recipe.semantic_language.to_be_bytes());
        hash.field("recipe_namespace", &recipe.namespace.to_be_bytes());
        hash.field("recipe_spelling", recipe.spelling.as_bytes());
    }
    Some(hash.finish())
}

pub(super) fn body_counts(
    paths: &PreparedPathRows,
    sites: &[PreparedSiteRow],
    typed: &PreparedTypedRows,
    gaps: &PreparedGapRows,
) -> [usize; BODY_MANIFEST_COLUMNS.len()] {
    [
        paths.rows.len(),
        sites.len(),
        gaps.rows.len(),
        gaps.reasons.len(),
        typed.type_frontiers.len(),
        typed.type_transfers.len(),
        typed.type_components.len(),
        typed.underlying_types.len(),
        typed.intrinsic_seeds.len(),
        typed.intrinsic_seed_identities.len(),
        typed.binding_projections.len(),
        typed.qualified_routes.len(),
        typed.declaration_types.len(),
        typed.deferred_member_owners.len(),
        typed.construction_requirements.len(),
        typed.supertypes.len(),
        typed.definition_property_gaps.len(),
        typed.call_obligations.len(),
        typed.callable_signatures.len(),
        typed.callable_parameter_owners.len(),
        0,
        0,
        0,
    ]
}

// One complete publication scans only the blob it just wrote. Warm admission
// reads the sealed totals and never repeats these body scans.
pub(super) const COMPLETE_PUBLICATION_COST_SQL: &str = "SELECT (SELECT COUNT(*) FROM resolution_rust_reference_contexts WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_rust_declaration_authorities WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_semantic_catalog WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_node_catalog WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_package_references WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_package_members WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_go_package_imports WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_contract_references WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_path_endpoint_headers WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_path_terminal_headers WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_reference_lookup_identities WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_root_route_segments WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_semantic_sites WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_additional_definition_namespaces WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_definition_unit_crosswalks WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_declaration_visibility_properties WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_member_scope_properties WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_member_owner_properties WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_trait_implementations WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_typed_fact_lookups WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_paths WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_sites WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_gaps WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_gap_reasons WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_type_frontiers WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_type_transfers WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_type_components WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_underlying_types WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_intrinsic_seeds WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_intrinsic_seed_identities WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_binding_projections WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_qualified_routes WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_declaration_types WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_deferred_member_owners WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_construction_requirements WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_supertypes WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_definition_property_gaps WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_call_obligations WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_callable_signatures WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_callable_parameter_owners WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_capsule_inputs WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_capsule_declarations WHERE blob_id = ?1),
       (SELECT COUNT(*) FROM resolution_capsule_reference_contexts WHERE blob_id = ?1),
       (SELECT COALESCE(SUM(COALESCE(length(CAST(cfg_condition AS BLOB)),0)),0) FROM resolution_rust_reference_contexts WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(visibility AS BLOB)),0) + COALESCE(length(CAST(cfg_condition AS BLOB)),0)),0) FROM resolution_rust_declaration_authorities WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(identity_digest AS BLOB)),0) + COALESCE(length(CAST(import_route_kind AS BLOB)),0)),0) FROM resolution_semantic_catalog WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(identity_digest AS BLOB)),0)),0) FROM resolution_node_catalog WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(length(CAST(namespace AS BLOB))),0) FROM resolution_package_references WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(length(CAST(namespace AS BLOB))),0) FROM resolution_package_members WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(length(CAST(kind AS BLOB))),0) FROM resolution_go_package_imports WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(direction AS BLOB)),0)),0) FROM resolution_path_endpoint_headers WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(direction AS BLOB)),0)),0) FROM resolution_path_terminal_headers WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(segment AS BLOB)),0) + COALESCE(length(CAST(terminal_spelling AS BLOB)),0)),0) FROM resolution_root_route_segments WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(namespace AS BLOB)),0) + COALESCE(length(CAST(semantic_role AS BLOB)),0)),0) FROM resolution_semantic_sites WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(namespace AS BLOB)),0) + COALESCE(length(CAST(hoisting AS BLOB)),0)),0) FROM resolution_additional_definition_namespaces WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(identity_digest AS BLOB)),0)),0) FROM resolution_definition_unit_crosswalks WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(visibility AS BLOB)),0)),0) FROM resolution_declaration_visibility_properties WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(member_kind AS BLOB)),0) + COALESCE(length(CAST(member_access AS BLOB)),0) + COALESCE(length(CAST(qualifier_compatibility AS BLOB)),0)),0) FROM resolution_member_owner_properties WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(side AS BLOB)),0) + COALESCE(length(CAST(segment AS BLOB)),0) + COALESCE(length(CAST(terminal_spelling AS BLOB)),0)),0) FROM resolution_trait_implementations WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(body AS BLOB)),0) + COALESCE(length(CAST(end_fixed_key AS BLOB)),0)),0) FROM resolution_paths WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(completion AS BLOB)),0)),0) FROM resolution_type_transfers WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(spelling AS BLOB)),0) + COALESCE(length(CAST(possible_values AS BLOB)),0) + COALESCE(length(CAST(completion AS BLOB)),0)),0) FROM resolution_intrinsic_seeds WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(body AS BLOB)),0)),0) FROM resolution_deferred_member_owners WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(argument_slots AS BLOB)),0) + COALESCE(length(CAST(type_argument_slots AS BLOB)),0) + COALESCE(length(CAST(eligible_rules AS BLOB)),0) + COALESCE(length(CAST(completion AS BLOB)),0)),0) FROM resolution_call_obligations WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(body AS BLOB)),0)),0) FROM resolution_callable_signatures WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(host_content_oid AS BLOB)),0) + COALESCE(length(CAST(definition_content_oid AS BLOB)),0) + COALESCE(length(CAST(producer_epoch AS BLOB)),0) + COALESCE(length(CAST(derivation_digest AS BLOB)),0) + COALESCE(length(CAST(checkpoint_digest AS BLOB)),0)),0) FROM resolution_capsule_inputs WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(identifier AS BLOB)),0) + COALESCE(length(CAST(kind AS BLOB)),0)),0) FROM resolution_capsule_declarations WHERE blob_id = ?1)
       + (SELECT COALESCE(SUM(COALESCE(length(CAST(lang AS BLOB)),0) + COALESCE(length(CAST(semantic_language AS BLOB)),0) + COALESCE(length(CAST(producer_epoch AS BLOB)),0) + COALESCE(length(CAST(interior_digest AS BLOB)),0)),0) FROM resolution_fragment_interiors WHERE blob_id = ?1)";

/// Pre-write grouping bound. SQLite's JSONB element header uses at most nine
/// bytes (one tag plus a u64 payload length); integer payloads retain their
/// decimal spelling. Shared IDs are u32 values, not prepared interning slots.
/// The committed writer measures actual encoding lengths instead.
fn estimated_body_bytes(body: &[PathBodyToken], cancellation: &CancellationToken) -> Option<usize> {
    const MAX_JSONB_HEADER_BYTES: usize = 1 + std::mem::size_of::<u64>();
    let mut bytes = 0usize;
    for token in body {
        if cancellation.is_cancelled() {
            return None;
        }
        let cell = match token {
            PathBodyToken::Close => 0,
            PathBodyToken::Open | PathBodyToken::Null => MAX_JSONB_HEADER_BYTES,
            PathBodyToken::Int(value) => MAX_JSONB_HEADER_BYTES + value.to_string().len(),
            PathBodyToken::Shared(_) => MAX_JSONB_HEADER_BYTES + 1 + u32::MAX.to_string().len(),
        };
        bytes = bytes.saturating_add(cell);
    }
    Some(bytes)
}

pub(super) fn estimated_body_payload_bytes(
    paths: &PreparedPathRows,
    typed: &PreparedTypedRows,
    cancellation: &CancellationToken,
) -> Option<usize> {
    let mut bytes = 0usize;
    for path in &paths.rows {
        if cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes.saturating_add(estimated_body_bytes(&path.body, cancellation)?);
        if let Some(endpoint) = &path.root_endpoint {
            let mut builder = RootKeyBuilder::default();
            for &(symbol, scoped) in &endpoint.symbols {
                if cancellation.is_cancelled() {
                    return None;
                }
                match symbol {
                    PathBodyToken::Int(local) => builder.push(Some(local), None, scoped),
                    PathBodyToken::Shared(_) => {
                        builder.push(None, Some(i64::from(u32::MAX)), scoped)
                    }
                    symbol => panic!("a root prefix cell is a structured identity: {symbol:?}"),
                }
            }
            bytes = bytes.saturating_add(builder.finish().0.len());
        }
    }
    for row in &typed.type_transfers {
        if cancellation.is_cancelled() {
            return None;
        }
        if let Some(body) = &row.completion {
            bytes = bytes.saturating_add(estimated_body_bytes(body, cancellation)?);
        }
    }
    for row in &typed.intrinsic_seeds {
        if cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes
            .saturating_add(row.spelling.len())
            .saturating_add(estimated_body_bytes(&row.possible_values, cancellation)?);
        if let Some(body) = &row.completion {
            bytes = bytes.saturating_add(estimated_body_bytes(body, cancellation)?);
        }
    }
    for row in &typed.deferred_member_owners {
        if cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes.saturating_add(estimated_body_bytes(&row.body, cancellation)?);
    }
    for row in &typed.call_obligations {
        if cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes
            .saturating_add(estimated_body_bytes(&row.argument_slots, cancellation)?)
            .saturating_add(estimated_body_bytes(
                &row.type_argument_slots,
                cancellation,
            )?)
            .saturating_add(estimated_body_bytes(&row.eligible_rules, cancellation)?);
        if let Some(body) = &row.completion {
            bytes = bytes.saturating_add(estimated_body_bytes(body, cancellation)?);
        }
    }
    for row in &typed.callable_signatures {
        if cancellation.is_cancelled() {
            return None;
        }
        bytes = bytes.saturating_add(estimated_body_bytes(&row.body, cancellation)?);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_proof_changes_invalidate_the_complete_body_identity() {
        let reference = PreparedSiteRow {
            site: 1,
            role: 0,
            namespace: 6,
            site_kind: Some(0),
            start_byte: Some(0),
            end_byte: Some(1),
            unqualified: Some(1),
            owner: None,
            receiver_origin: None,
            go_spelling_namespace: Some(6),
            go_definition_namespaces: None,
            go_package_qualifier: false,
        };
        let digest = |site: &PreparedSiteRow| {
            complete_body_digest(
                [7; 32],
                &PreparedPathRows::default(),
                std::slice::from_ref(site),
                &PreparedTypedRows::default(),
                &PreparedGapRows::default(),
                &[],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        };
        let original = digest(&reference);
        let mut qualifier = reference;
        qualifier.go_package_qualifier = true;
        assert_ne!(
            digest(&qualifier),
            original,
            "package admission changes answer authority"
        );
        let mut without_proof = reference;
        without_proof.go_spelling_namespace = None;
        assert_ne!(
            digest(&without_proof),
            original,
            "missing spelling proof is incomplete evidence"
        );
        let mut definition = PreparedSiteRow {
            site: 2,
            role: 1,
            namespace: 0,
            site_kind: None,
            start_byte: None,
            end_byte: None,
            unqualified: None,
            owner: None,
            receiver_origin: None,
            go_spelling_namespace: None,
            go_definition_namespaces: Some(1),
            go_package_qualifier: false,
        };
        let type_identity = digest(&definition);
        definition.namespace = 7;
        definition.go_definition_namespaces = Some(8);
        let package_identity = digest(&definition);
        definition.go_definition_namespaces = None;
        assert_ne!(
            digest(&definition),
            package_identity,
            "namespace eligibility is separately authenticated"
        );
        assert_ne!(type_identity, package_identity);
    }

    #[test]
    fn callable_parameter_owner_digest_is_order_independent_and_owner_sensitive() {
        let mut typed = PreparedTypedRows {
            callable_parameter_owners: vec![
                PreparedCallableParameterOwnerRow {
                    parameter_definition: 2,
                    signature_definition: 1,
                },
                PreparedCallableParameterOwnerRow {
                    parameter_definition: 4,
                    signature_definition: 3,
                },
            ],
            ..Default::default()
        };
        let digest = |typed: &PreparedTypedRows| {
            complete_body_digest(
                [7; 32],
                &PreparedPathRows::default(),
                &[],
                typed,
                &PreparedGapRows::default(),
                &[],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        };
        let original = digest(&typed);
        typed.callable_parameter_owners.reverse();
        assert_eq!(digest(&typed), original);
        typed.callable_parameter_owners[0].signature_definition = 1;
        assert_ne!(digest(&typed), original);
    }

    #[test]
    fn body_identity_is_independent_of_row_order_and_shared_intern_order() {
        let row = PreparedPathRow {
            path: 1,
            start_node: 2,
            start_lead_local: None,
            start_lead_shared: Some(0),
            start_lead_scoped: false,
            end_node: -1,
            end_lead_local: None,
            end_lead_shared: Some(1),
            end_lead_scoped: true,
            root_terminal: Some(1),
            root_endpoint: Some(PreparedRootEndpoint {
                symbols: vec![(PathBodyToken::Shared(1), true)],
                open_tail: false,
            }),
            body: vec![
                PathBodyToken::Open,
                PathBodyToken::Shared(0),
                PathBodyToken::Open,
                PathBodyToken::Shared(1),
                PathBodyToken::Null,
                PathBodyToken::Close,
                PathBodyToken::Close,
            ],
        };
        let mut second = row.clone();
        second.path = 3;
        let original = PreparedPathRows {
            shared: vec![[1; 32], [2; 32]],
            rows: vec![row, second],
        };
        let digest = |paths: &PreparedPathRows| {
            complete_body_digest(
                [7; 32],
                paths,
                &[],
                &PreparedTypedRows::default(),
                &PreparedGapRows::default(),
                &[],
                &[[1; 32], [2; 32]],
                &CancellationToken::default(),
            )
            .unwrap()
        };
        let expected = digest(&original);
        let mut reordered = original.clone();
        reordered.rows.reverse();
        reordered.shared.reverse();
        for row in &mut reordered.rows {
            row.start_lead_shared = row.start_lead_shared.map(|slot| 1 - slot);
            row.end_lead_shared = row.end_lead_shared.map(|slot| 1 - slot);
            row.root_terminal = row.root_terminal.map(|slot| 1 - slot);
            for token in &mut row.body {
                if let PathBodyToken::Shared(slot) = token {
                    *slot = 1 - *slot;
                }
            }
            for (token, _) in &mut row.root_endpoint.as_mut().unwrap().symbols {
                if let PathBodyToken::Shared(slot) = token {
                    *slot = 1 - *slot;
                }
            }
        }
        assert_eq!(digest(&reordered), expected);
        reordered.rows[0].body[4] = PathBodyToken::Int(9);
        assert_ne!(
            digest(&reordered),
            expected,
            "a body-only change changes complete identity"
        );
    }
}
