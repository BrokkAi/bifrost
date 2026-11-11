-- One selected owning crate. Every arm is restricted by the selected unit key.
-- The reader folds rows in this order and never retains a crate-sized index.
WITH selected AS MATERIALIZED (
  SELECT u.summary_id, u.topology_id, u.unit_key,
         u.workspace_id, u.lang, u.generation, u.revision,
         s.summary_digest,
         s.complete AS summary_complete, s.publication_state AS summary_state,
         t.topology_digest, t.inventory_complete AS topology_complete,
         t.publication_state AS topology_state,
         COALESCE(c.inventory_complete, 0) AS context_complete
  FROM selected_rust_unit_summaries AS u
  JOIN resolution_unit_summaries AS s ON s.summary_id = u.summary_id
  JOIN rust_crate_topologies AS t ON t.topology_id = u.topology_id
  LEFT JOIN rust_resolution_unit_summary_contexts AS c ON c.summary_id = u.summary_id
  WHERE u.unit_key = ?1
), members AS MATERIALIZED (
  SELECT m.summary_id, m.member_ordinal, m.rel_path, m.blob_id,
         blob.blob_oid, f.publication_state AS source_state,
         (live.file_version_id IS NULL OR live.blob_oid <> blob.blob_oid) AS live_mismatch,
         i.facts_version,
         census.census_version, census.impl_count, census.boundary_count,
         (SELECT count(*) FROM source_rust_impl_items AS impl
          WHERE impl.blob_id = m.blob_id) AS actual_impl_count,
         (SELECT count(*) FROM source_rust_impl_census_boundaries AS boundary
          WHERE boundary.blob_id = m.blob_id) AS actual_boundary_count
  FROM selected AS s
  CROSS JOIN resolution_unit_summary_members AS m ON m.summary_id = s.summary_id
  JOIN blobs AS blob ON blob.id = m.blob_id
  LEFT JOIN workspace_file_versions AS live
    ON live.workspace_id = s.workspace_id AND live.lang = s.lang
   AND live.generation = s.generation AND live.rel_path = m.rel_path
   AND live.input_kind = 'source' AND live.valid_from <= s.revision
   AND (live.valid_until IS NULL OR s.revision < live.valid_until)
  LEFT JOIN source_fact_manifests AS f ON f.blob_id = m.blob_id
  LEFT JOIN source_rust_item_manifests AS i ON i.blob_id = m.blob_id
  LEFT JOIN source_rust_impl_census_files AS census ON census.blob_id = m.blob_id
), pairs AS MATERIALIZED (
  SELECT subject.summary_id, subject.member_ordinal,
         subject.owner_module_path, subject.source_relation_key,
         subject.impl_declaration_id, subject.endpoint_state AS subject_state,
         subject.unresolved_spelling AS subject_spelling,
         subject.unresolved_reason AS subject_reason,
         subject.target_unit_key AS subject_unit,
         subject.target_module_path AS subject_module,
         subject_identity.identity_digest AS subject_identity,
         subject_kind.declaration_kind AS subject_kind,
         trait.endpoint_state AS trait_state,
         trait_identity.identity_digest AS trait_identity
  FROM selected AS s
  CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS subject
    ON subject.summary_id = s.summary_id
  LEFT JOIN rust_resolution_unit_summary_trait_endpoints AS trait
    ON trait.summary_id = subject.summary_id
   AND trait.member_ordinal = subject.member_ordinal
   AND trait.owner_module_path = subject.owner_module_path
   AND trait.source_relation_key = subject.source_relation_key
   AND trait.endpoint_role = 'trait'
  LEFT JOIN resolution_identities AS subject_identity
    ON subject_identity.id = subject.target_identity_id
  LEFT JOIN resolution_identities AS trait_identity
    ON trait_identity.id = trait.target_identity_id
  LEFT JOIN selected_rust_unit_summaries AS target_unit
    ON target_unit.unit_key = subject.target_unit_key
  LEFT JOIN rust_resolution_unit_summary_exports AS target_export
    ON target_export.summary_id = target_unit.summary_id
   AND target_export.identity_id = subject.target_identity_id
   AND target_export.origin = 'declaration'
  LEFT JOIN resolution_unit_summary_members AS target_member
    ON target_member.summary_id = target_unit.summary_id
   AND target_member.member_ordinal = target_export.declaration_member_ordinal
  LEFT JOIN resolution_rust_declaration_authorities AS target_authority
    ON target_authority.blob_id = target_member.blob_id
   AND target_authority.source_site = target_export.declaration_site
  LEFT JOIN source_rust_declaration_properties AS subject_kind
    ON subject_kind.blob_id = target_member.blob_id
   AND subject_kind.declaration_id = target_authority.declaration
  WHERE subject.endpoint_role = 'subject'
)
SELECT 0 AS row_kind,
       s.unit_key, s.summary_digest, s.topology_digest,
       s.summary_complete, s.summary_state, s.topology_complete,
       s.topology_state, s.context_complete,
       EXISTS(SELECT 1 FROM rust_resolution_unit_summary_exports AS target
              JOIN resolution_identities AS identity ON identity.id = target.identity_id
              WHERE target.summary_id = s.summary_id
                AND target.origin = 'declaration' AND target.namespace = 'type'
                AND target.module_path = ?3 AND identity.identity_digest = ?4
                AND s.unit_key = ?2), NULL, NULL, NULL, NULL
FROM selected AS s
UNION ALL
SELECT 1, m.rel_path, hex(m.blob_oid), m.source_state,
       m.facts_version, m.census_version, m.impl_count,
       m.actual_impl_count, m.boundary_count,
       (SELECT count(*) FROM rust_resolution_unit_summary_binding_completeness AS b
        WHERE b.summary_id = m.summary_id AND b.member_ordinal = m.member_ordinal
          AND b.complete = 0), m.actual_boundary_count, m.live_mismatch, NULL, NULL
FROM members AS m
UNION ALL
SELECT 2, m.rel_path, hex(m.blob_oid), b.ordinal, b.kind, b.start_byte,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM members AS m
JOIN source_rust_impl_census_boundaries AS b ON b.blob_id = m.blob_id
UNION ALL
SELECT 3, m.rel_path, hex(m.blob_oid), impl.declaration_id,
       impl.trait_type_occurrence_id IS NOT NULL,
       (SELECT count(*) FROM pairs AS p
        WHERE p.summary_id = m.summary_id AND p.member_ordinal = m.member_ordinal
          AND p.impl_declaration_id = impl.declaration_id),
       (SELECT count(*) FROM rust_crate_inherent_impls AS h
        JOIN selected AS s ON s.topology_id = h.topology_id
        WHERE h.impl_blob_id = m.blob_id
          AND h.impl_declaration_id = impl.declaration_id),
       (SELECT count(*) FROM rust_crate_unresolved_inherent_impls AS h
        JOIN selected AS s ON s.topology_id = h.topology_id
        WHERE h.impl_blob_id = m.blob_id
          AND h.impl_declaration_id = impl.declaration_id),
       NULL, NULL, NULL, NULL, NULL, NULL
FROM members AS m
JOIN source_rust_impl_items AS impl ON impl.blob_id = m.blob_id
UNION ALL
SELECT 4, m.rel_path, hex(m.blob_oid), p.impl_declaration_id,
       p.owner_module_path, p.source_relation_key, p.subject_state,
       p.subject_unit, p.subject_module, p.subject_identity,
       p.subject_kind, p.trait_state, p.trait_identity,
       (SELECT count(*) FROM source_rust_impl_items AS impl
        WHERE impl.blob_id = m.blob_id AND impl.declaration_id = p.impl_declaration_id)
FROM members AS m
JOIN pairs AS p ON p.summary_id = m.summary_id
 AND p.member_ordinal = m.member_ordinal
UNION ALL
SELECT 9, m.rel_path, hex(m.blob_oid), h.impl_declaration_id,
       h.subject_declaration_site, property.declaration_kind,
       h.subject_rel_path,
       (SELECT count(*) FROM resolution_rust_declaration_authorities AS bridge
        WHERE bridge.blob_id = h.subject_declaration_blob_id
          AND bridge.source_site = h.subject_declaration_site),
       NULL, NULL, NULL, NULL, NULL, NULL
FROM members AS m
JOIN selected AS s ON s.summary_id = m.summary_id
JOIN rust_crate_inherent_impls AS h
  ON h.topology_id = s.topology_id AND h.impl_blob_id = m.blob_id
LEFT JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id = h.subject_declaration_blob_id
 AND authority.source_site = h.subject_declaration_site
LEFT JOIN source_rust_declaration_properties AS property
  ON property.blob_id = authority.blob_id AND property.declaration_id = authority.declaration
UNION ALL
SELECT 5, g.gap_kind, g.subject, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM selected AS s
JOIN rust_crate_gaps AS g ON g.topology_id = s.topology_id
UNION ALL
SELECT 7, source.rel_path, NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM selected AS s
CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id = s.topology_id
WHERE NOT EXISTS (
  SELECT 1 FROM resolution_unit_summary_members AS m
  WHERE m.summary_id = s.summary_id AND m.blob_id = source.blob_id
    AND m.rel_path = source.rel_path)
UNION ALL
SELECT 8, e.owner_module_path, e.source_relation_key,
       e.impl_declaration_id, e.endpoint_role, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM selected AS s
CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS e
  ON e.summary_id = s.summary_id AND e.endpoint_role = 'trait'
WHERE NOT EXISTS (
  SELECT 1 FROM rust_resolution_unit_summary_trait_endpoints AS subject
  WHERE subject.summary_id = e.summary_id
    AND subject.member_ordinal = e.member_ordinal
    AND subject.owner_module_path = e.owner_module_path
    AND subject.source_relation_key = e.source_relation_key
    AND subject.endpoint_role = 'subject')
ORDER BY row_kind, 2, 3, 4, 5, 6;
