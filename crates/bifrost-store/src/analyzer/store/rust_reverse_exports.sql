-- One declaration, including every selected named and glob re-export route.
-- Seed from the placed member row, then follow Rust-owned route targets. The
-- summary id keeps every route inside the referenced live unit version.
WITH RECURSIVE exposed(summary_id, topology_id, crate_key, module_path, namespace,
                       name, visibility, depth) AS (
  SELECT exports.summary_id, owner.topology_id, owner.unit_key,
         exports.module_path, exports.namespace, exports.name,
         exports.visibility, 0
  FROM main.resolution_unit_summary_members AS member
    INDEXED BY resolution_unit_summary_members_path
  CROSS JOIN selected_rust_unit_summaries AS owner
    ON owner.summary_id = member.summary_id
  -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
  CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
    INDEXED BY rust_resolution_unit_summary_exports_declaration
    ON exports.summary_id=member.summary_id
   AND exports.declaration_member_ordinal=member.member_ordinal
   AND exports.declaration_site=?2
   AND exports.origin = 'declaration'
  LEFT JOIN main.resolution_unit_summary_exports AS shared_export
    INDEXED BY resolution_unit_summary_exports_surface_lookup
    ON shared_export.summary_id=member.summary_id
   AND shared_export.declaration_member_ordinal=(
       SELECT min(shared_member.member_ordinal)
       FROM main.resolution_unit_summary_members AS shared_member
        INDEXED BY resolution_unit_summary_members_blob
       WHERE shared_member.summary_id=member.summary_id
         AND shared_member.blob_id=member.blob_id)
   AND shared_export.site_surface_ordinal=(
       SELECT site.surface_ordinal
       FROM temp.surface_dense AS site
       WHERE site.blob_id=?1 AND site.id_space=0 AND site.dense_id=?2)
   AND shared_export.identity_id=exports.identity_id
   AND shared_export.namespace=exports.namespace
   AND shared_export.target_kind='own'
  CROSS JOIN temp.rust_unit_summary_placements AS placement
    ON placement.summary_id = member.summary_id
   AND placement.member_ordinal = member.member_ordinal
   AND (placement.module_path = exports.module_path
        OR (exports.namespace = 'macro' AND exports.module_path = 'crate'))
  WHERE member.rel_path = ?3
    -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
    AND member.blob_id=?1
    AND (exports.visibility<>'public' OR shared_export.identity_id IS NOT NULL)
  UNION
  SELECT owner.summary_id, owner.topology_id, owner.unit_key,
         routes.module_path, target.namespace, routes.bound_name,
         routes.visibility, target.depth + 1
  FROM exposed AS target
  CROSS JOIN main.rust_resolution_unit_summary_reexport_routes AS routes
    INDEXED BY rust_resolution_unit_summary_reexport_routes_target_identity
    ON routes.target_unit_key = target.crate_key
   AND routes.target_module_path = target.module_path
   AND routes.target_name = target.name
  CROSS JOIN selected_rust_unit_summaries AS owner
    ON owner.summary_id = routes.summary_id
  WHERE target.visibility <> 'private'
    AND (target.visibility = 'public' OR target.crate_key = owner.unit_key)
    AND target.depth < 64
  UNION
  SELECT owner.summary_id, owner.topology_id, owner.unit_key,
         routes.module_path, target.namespace, target.name,
         routes.visibility, target.depth + 1
  FROM exposed AS target
  CROSS JOIN main.rust_resolution_unit_summary_glob_reexport_routes AS routes
    INDEXED BY rust_resolution_unit_summary_glob_reexport_routes_target_identity
    ON routes.target_unit_key = target.crate_key
   AND routes.target_module_path = target.module_path
  CROSS JOIN selected_rust_unit_summaries AS owner
    ON owner.summary_id = routes.summary_id
  WHERE target.visibility <> 'private'
    AND (target.visibility = 'public' OR target.crate_key = owner.unit_key)
    AND target.depth < 64
)
SELECT topology_id, crate_key, module_path, namespace, name, visibility, depth
FROM exposed;
