//! Ordinary keyed authority statements shared with the production plan pins.

pub(crate) const SEMANTIC_PROVENANCE_SQL: &str = "SELECT identity_digest, shared_identity FROM resolution_semantic_catalog WHERE blob_id=?1 AND local_key=?2 AND identity_digest IS NOT NULL";

pub(crate) const NODE_PROVENANCE_SQL: &str =
    "SELECT identity_digest FROM resolution_node_catalog WHERE blob_id=?1 AND local_key=?2";

pub(crate) const SEMANTIC_SITES_SQL: &str =
    "SELECT site, namespace FROM resolution_sites WHERE blob_id=?1 AND site=?2 AND role=?4";

pub(crate) const SEMANTIC_SITES_2_SQL: &str = "SELECT site, namespace FROM resolution_sites WHERE blob_id=?1 AND start_byte=?2 AND end_byte=?3 AND role=?4 ORDER BY site";

pub(crate) const SEMANTIC_SITES_3_SQL: &str = "SELECT s.site, s.namespace FROM source_declarations d JOIN source_native_declaration_bridges b ON b.blob_id=d.blob_id AND b.declaration_id=d.declaration_id JOIN resolution_sites s ON s.blob_id=b.blob_id AND s.site=b.source_site WHERE d.blob_id=?1 AND d.name_start_byte=?2 AND d.name_end_byte=?3 AND s.role=?4 ORDER BY s.site";

pub(crate) const SCOPE_ORDINALS_SQL: &str = "SELECT local_key, source_scope, identity_digest FROM resolution_node_catalog WHERE blob_id=?1 AND local_key IN (SELECT value FROM json_each(?2)) ORDER BY local_key";

pub(crate) const SEMANTIC_FOR_IDENTITY_SQL: &str =
    "SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND identity_digest=?2";

pub(crate) const SEMANTIC_FOR_IDENTITY_2_SQL: &str = "SELECT shared_identity FROM resolution_semantic_catalog WHERE blob_id=?1 AND shared_identity=?2";

pub(crate) const SEMANTICS_FOR_IDENTITIES_SQL: &str = "SELECT k.key,c.local_key FROM json_each(?2) k JOIN resolution_semantic_catalog c ON c.blob_id=?1 AND c.identity_digest=unhex(k.value) ORDER BY k.key";

pub(crate) const NODE_FOR_IDENTITY_SQL: &str =
    "SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 AND identity_digest=?2";

pub(crate) const SCOPE_START_PATHS_SQL: &str = "SELECT p.path FROM resolution_node_catalog n JOIN resolution_paths p ON p.blob_id=n.blob_id AND p.start_node=n.local_key WHERE n.blob_id=?1 AND n.source_scope=?2 ORDER BY p.path";

pub(crate) const REFERENCE_LOOKUP_SPELLING_SQL: &str = "SELECT p.start_node, i.spelling FROM resolution_paths p JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 JOIN resolution_identities i ON i.id=p.end_lead_identity WHERE p.blob_id=?1 AND p.start_node IN (SELECT value FROM json_each(?2)) AND i.namespace=?3 ORDER BY p.start_node,p.path";

pub(crate) const DEFINITION_SOURCE_SITE_SQL: &str =
    "SELECT site FROM resolution_sites WHERE blob_id=?1 AND site=?2 AND role=1";

pub(crate) const ROOT_EXPORT_HALVES_SQL: &str = "SELECT i.semantic_language, i.namespace, i.spelling, (json_array_length(p.body,'$[0]')=2 AND json_array_length(p.body,'$[4]')=0 AND json_type(p.body,'$[1]')='integer' AND json_extract(p.body,'$[1]')=json_extract(p.body,'$[5]')) FROM resolution_paths p JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.end_node AND s.role=1 JOIN resolution_identities i ON i.id=p.start_lead_identity WHERE p.blob_id=?1 AND p.end_node=?2 AND p.start_node=-1 AND i.namespace IS NOT NULL ORDER BY p.path";

pub(crate) const LOOKUP_RECIPES_SQL: &str = "SELECT i.semantic_language, i.namespace, i.spelling FROM resolution_semantic_catalog c JOIN resolution_identities i ON i.id=c.shared_identity WHERE c.blob_id=?1 AND i.namespace IS NOT NULL ORDER BY c.local_key";

pub(crate) const UNSUPPORTED_GAP_REASONS_SQL: &str = "SELECT reason FROM resolution_gap_reasons WHERE blob_id=?1 AND site=?2 AND origin=?3 UNION ALL SELECT reason FROM resolution_gap_reasons WHERE blob_id=?1 AND site=?2 AND origin=?4 UNION ALL SELECT reason FROM resolution_gap_reasons WHERE blob_id=?1 AND site=?2 AND origin=?5 ORDER BY reason";

pub(crate) const TYPE_IDENTITY_OBSERVATION_SITES_SQL: &str = "SELECT p.output_slot FROM resolution_sites s JOIN resolution_binding_projections p ON p.blob_id=s.blob_id AND p.reference=s.site WHERE s.blob_id=?1 AND s.site=?2 AND p.kind IN (?3,?4) ORDER BY p.output_slot";

pub(crate) const TYPE_IDENTITY_OBSERVATION_SITES_2_SQL: &str = "SELECT s.site FROM resolution_type_frontiers f JOIN resolution_sites s ON s.blob_id=f.blob_id AND s.site=f.identity_reference AND s.role=0 WHERE f.blob_id=?1 AND f.slot=?2";

pub(crate) const TYPE_IDENTITY_OBSERVATION_SITES_3_SQL: &str = "SELECT target_slot FROM resolution_type_transfers WHERE blob_id=?1 AND source_slot=?2 AND kind=?3 ORDER BY target_slot,indirection_delta,reference_indirection_delta,rule";

pub(crate) const CONTRACT_REFERENCE_SITES_SQL: &str = "SELECT reference_site FROM resolution_contract_references WHERE blob_id=?1 AND definition=?2 AND member_kind=?3 ORDER BY position";

pub(crate) const QUALIFIED_ROUTE_REFERENCE_SITES_SQL: &str = "SELECT s.site FROM resolution_qualified_routes q JOIN resolution_sites s ON s.blob_id=q.blob_id AND s.site=q.reference AND s.role=0 WHERE q.blob_id=?1 AND q.source_lookup=?2 ORDER BY q.reference,q.precedence_ordinal";

pub(crate) const READ_AUTHORITY_SQL: &str = "SELECT 1 FROM resolution_fragment_interiors WHERE blob_id=?1 AND lang=?2 AND semantic_language=?3 AND producer_epoch=?4 AND interior_digest=?5 AND publication_state='complete'";

pub(crate) const REVERSE_COMPLETION_WITH_EXCLUSIONS_SQL: &str =
    "SELECT mount_ordinal FROM temp.selected_resolution_scope_mounts";

pub(crate) const REVERSE_COMPLETION_WITH_EXCLUSIONS_2_SQL: &str = "SELECT m.mount_ordinal,g.covers,g.subject FROM json_each(?1) k JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=k.value->>0 JOIN resolution_gaps g ON g.blob_id=m.blob_id AND g.gap=k.value->>1 WHERE g.covers IN (3,6) AND NOT EXISTS(SELECT 1 FROM resolution_gap_reasons r JOIN resolution_qualified_routes q ON q.blob_id=r.blob_id AND q.reference=r.site AND q.coarse_gap_reason=r.reason WHERE r.blob_id=g.blob_id AND r.reason=g.reason AND r.origin=?2)";

pub(crate) const REVERSE_COMPLETION_WITH_EXCLUSIONS_3_SQL: &str = "SELECT m.mount_ordinal,g.covers,g.subject,g.lookup,g.gap,g.reason FROM temp.selected_resolution_mounts m JOIN resolution_gaps g ON g.blob_id=m.blob_id AND g.covers IN (0,3) WHERE NOT EXISTS(SELECT 1 FROM resolution_gap_reasons r JOIN resolution_qualified_routes q ON q.blob_id=r.blob_id AND q.reference=r.site AND q.coarse_gap_reason=r.reason WHERE r.blob_id=g.blob_id AND r.reason=g.reason AND r.origin=?2) UNION ALL SELECT m.mount_ordinal,g.covers,g.subject,g.lookup,g.gap,g.reason FROM json_each(?1) k JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=k.value->>0 JOIN resolution_gaps g ON g.blob_id=m.blob_id AND g.covers=6 AND g.subject=k.value->>1 WHERE k.value->>0>=0 AND NOT EXISTS(SELECT 1 FROM resolution_gap_reasons r JOIN resolution_qualified_routes q ON q.blob_id=r.blob_id AND q.reference=r.site AND q.coarse_gap_reason=r.reason WHERE r.blob_id=g.blob_id AND r.reason=g.reason AND r.origin=?2) UNION ALL SELECT m.mount_ordinal,g.covers,g.subject,g.lookup,g.gap,g.reason FROM json_each(?1) k CROSS JOIN temp.selected_resolution_mounts m JOIN resolution_gaps g ON g.blob_id=m.blob_id AND g.covers=6 AND g.subject=-1 WHERE k.value->>0=-1 AND NOT EXISTS(SELECT 1 FROM resolution_gap_reasons r JOIN resolution_qualified_routes q ON q.blob_id=r.blob_id AND q.reference=r.site AND q.coarse_gap_reason=r.reason WHERE r.blob_id=g.blob_id AND r.reason=g.reason AND r.origin=?2)";

pub(crate) const ENUMERATION_COMPLETION_SQL: &str = "SELECT g.reason FROM resolution_gaps g JOIN resolution_gap_reasons r ON r.blob_id=g.blob_id AND r.reason=g.reason WHERE g.blob_id=?1 AND g.covers IN (0,1) AND NOT(r.origin=?2 AND EXISTS(SELECT 1 FROM resolution_qualified_routes q WHERE q.blob_id=g.blob_id AND q.reference=r.site AND q.coarse_gap_reason=g.reason)) ORDER BY g.reason";

pub(crate) const VISIT_MOUNT_REFERENCE_SEEDS_SQL: &str =
    "SELECT site FROM resolution_sites WHERE blob_id=?1 AND role=0 ORDER BY site";

pub(crate) const ROOT_DEMAND_SHARED_SQL: &str = "SELECT s.site, (json_array_length(p.body,'$[4]')>3 AND NOT EXISTS(SELECT 1 FROM resolution_identities i WHERE i.id=-coalesce(json_extract(p.body,'$[4][1][0]'),json_extract(p.body,'$[4][1]')) AND i.namespace IS NOT NULL)) FROM resolution_paths p INDEXED BY resolution_paths_root_terminal JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_node=-1 AND json_array_length(p.body,'$[4]')>=3 AND p.root_terminal=?2 ORDER BY p.path";

pub(crate) const IMPORTED_ROOT_DEMAND_SHARED_SQL: &str = "SELECT DISTINCT s.site FROM resolution_paths p INDEXED BY resolution_paths_root_terminal JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 JOIN resolution_identities head ON head.id=-coalesce(json_extract(p.body,'$[4][1][0]'),json_extract(p.body,'$[4][1]')) JOIN source_rust_import_targets imported ON imported.blob_id=p.blob_id AND imported.bound_name=head.spelling AND imported.is_glob=0 WHERE p.blob_id=?1 AND p.end_node=-1 AND json_array_length(p.body,'$[4]')>=3 AND p.root_terminal=?2 ORDER BY s.site";

pub(crate) const ROOT_DEMAND_LOCAL_SQL: &str = "SELECT s.site, (json_array_length(p.body,'$[4]')>3 AND NOT EXISTS(SELECT 1 FROM resolution_identities i WHERE i.id=-coalesce(json_extract(p.body,'$[4][1][0]'),json_extract(p.body,'$[4][1]')) AND i.namespace IS NOT NULL)) FROM resolution_paths p INDEXED BY resolution_paths_root_local_terminal JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_node=-1 AND json_array_length(p.body,'$[4]')>=3 AND coalesce(json_extract(p.body,'$[4][#-1][0]'),json_extract(p.body,'$[4][#-1]'))=?2 ORDER BY p.path";

pub(crate) const LOOKUP_REFERENCE_SHARED_SQL: &str = "SELECT s.site FROM resolution_paths p INDEXED BY resolution_paths_end_lookup_identity JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_lead_identity=?2 AND ?3 IS NULL ORDER BY p.path";

pub(crate) const LOOKUP_REFERENCE_LOCAL_SQL: &str = "SELECT s.site FROM resolution_paths p INDEXED BY resolution_paths_end_lookup_local JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_lead_local=?2 AND ?3 IS NULL ORDER BY p.path";

pub(crate) const SCOPED_LOOKUP_REFERENCE_SHARED_SQL: &str = "WITH RECURSIVE reached(node) AS (SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 AND source_scope=?3 UNION SELECT p.start_node FROM reached r CROSS JOIN resolution_paths p INDEXED BY resolution_paths_reverse ON p.blob_id=?1 AND p.end_node=r.node WHERE p.start_node<>-1 AND p.start_lead_local IS NULL AND p.start_lead_identity IS NULL AND p.end_lead_local IS NULL AND p.end_lead_identity IS NULL) SELECT s.site FROM resolution_paths p INDEXED BY resolution_paths_end_lookup_identity JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_lead_identity=?2 AND p.end_node IN (SELECT node FROM reached) ORDER BY p.path";

pub(crate) const SCOPED_LOOKUP_REFERENCE_LOCAL_SQL: &str = "WITH RECURSIVE reached(node) AS (SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 AND source_scope=?3 UNION SELECT p.start_node FROM reached r CROSS JOIN resolution_paths p INDEXED BY resolution_paths_reverse ON p.blob_id=?1 AND p.end_node=r.node WHERE p.start_node<>-1 AND p.start_lead_local IS NULL AND p.start_lead_identity IS NULL AND p.end_lead_local IS NULL AND p.end_lead_identity IS NULL) SELECT s.site FROM resolution_paths p INDEXED BY resolution_paths_end_lookup_local JOIN resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0 WHERE p.blob_id=?1 AND p.end_lead_local=?2 AND p.end_node IN (SELECT node FROM reached) ORDER BY p.path";

#[cfg(test)]
pub(crate) const PINNED_SQL: &[(&str, &str)] = &[
    ("semantic_provenance_sql", SEMANTIC_PROVENANCE_SQL),
    ("node_provenance_sql", NODE_PROVENANCE_SQL),
    ("semantic_sites_sql", SEMANTIC_SITES_SQL),
    ("semantic_sites_2_sql", SEMANTIC_SITES_2_SQL),
    ("semantic_sites_3_sql", SEMANTIC_SITES_3_SQL),
    ("scope_ordinals_sql", SCOPE_ORDINALS_SQL),
    ("semantic_for_identity_sql", SEMANTIC_FOR_IDENTITY_SQL),
    ("semantics_for_identities_sql", SEMANTICS_FOR_IDENTITIES_SQL),
    ("semantic_for_identity_2_sql", SEMANTIC_FOR_IDENTITY_2_SQL),
    ("node_for_identity_sql", NODE_FOR_IDENTITY_SQL),
    ("scope_start_paths_sql", SCOPE_START_PATHS_SQL),
    (
        "reference_lookup_spelling_sql",
        REFERENCE_LOOKUP_SPELLING_SQL,
    ),
    ("definition_source_site_sql", DEFINITION_SOURCE_SITE_SQL),
    ("root_export_halves_sql", ROOT_EXPORT_HALVES_SQL),
    ("lookup_recipes_sql", LOOKUP_RECIPES_SQL),
    ("unsupported_gap_reasons_sql", UNSUPPORTED_GAP_REASONS_SQL),
    (
        "type_identity_observation_sites_sql",
        TYPE_IDENTITY_OBSERVATION_SITES_SQL,
    ),
    (
        "type_identity_observation_sites_2_sql",
        TYPE_IDENTITY_OBSERVATION_SITES_2_SQL,
    ),
    (
        "type_identity_observation_sites_3_sql",
        TYPE_IDENTITY_OBSERVATION_SITES_3_SQL,
    ),
    ("contract_reference_sites_sql", CONTRACT_REFERENCE_SITES_SQL),
    (
        "qualified_route_reference_sites_sql",
        QUALIFIED_ROUTE_REFERENCE_SITES_SQL,
    ),
    ("read_authority_sql", READ_AUTHORITY_SQL),
    (
        "reverse_completion_with_exclusions_sql",
        REVERSE_COMPLETION_WITH_EXCLUSIONS_SQL,
    ),
    (
        "reverse_completion_with_exclusions_2_sql",
        REVERSE_COMPLETION_WITH_EXCLUSIONS_2_SQL,
    ),
    (
        "reverse_completion_with_exclusions_3_sql",
        REVERSE_COMPLETION_WITH_EXCLUSIONS_3_SQL,
    ),
    ("enumeration_completion_sql", ENUMERATION_COMPLETION_SQL),
    (
        "visit_mount_reference_seeds_sql",
        VISIT_MOUNT_REFERENCE_SEEDS_SQL,
    ),
    ("root_demand_shared_sql", ROOT_DEMAND_SHARED_SQL),
    (
        "imported_root_demand_shared_sql",
        IMPORTED_ROOT_DEMAND_SHARED_SQL,
    ),
    ("root_demand_local_sql", ROOT_DEMAND_LOCAL_SQL),
    ("lookup_reference_shared_sql", LOOKUP_REFERENCE_SHARED_SQL),
    ("lookup_reference_local_sql", LOOKUP_REFERENCE_LOCAL_SQL),
    (
        "scoped_lookup_reference_shared_sql",
        SCOPED_LOOKUP_REFERENCE_SHARED_SQL,
    ),
    (
        "scoped_lookup_reference_local_sql",
        SCOPED_LOOKUP_REFERENCE_LOCAL_SQL,
    ),
];
