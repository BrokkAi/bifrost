-- Resolve one selected namespace/name at each demanded glob destination. Historical
-- declaration evidence is deliberately not compared to current target blobs.
INSERT OR IGNORE INTO cr_surface_lookup
SELECT pending.owner_crate_key, pending.owner_module_path, pending.owner_namespace, pending.owner_name,
       pending.crate_key, pending.module_path, pending.name, exports.origin
FROM cr_surface_pending AS pending
CROSS JOIN cr_exports AS exports
  ON exports.crate_key = pending.crate_key
 AND exports.module_path = pending.module_path
 AND exports.namespace = pending.owner_namespace AND exports.name = pending.name
WHERE exports.crate_key = (SELECT crate_key FROM cr_identity)
  AND exports.visibility = 'public'
UNION ALL
SELECT pending.owner_crate_key, pending.owner_module_path, pending.owner_namespace, pending.owner_name,
       pending.crate_key, pending.module_path, pending.name, exports.origin
FROM cr_surface_pending AS pending
CROSS JOIN cr_foreign AS foreign_crate ON foreign_crate.crate_key = pending.crate_key
CROSS JOIN rust_crate_exports AS exports
  ON exports.topology_id = foreign_crate.topology_id
 AND exports.module_path = pending.module_path
 AND exports.namespace = pending.owner_namespace AND exports.name = pending.name
WHERE exports.visibility = 'public';
