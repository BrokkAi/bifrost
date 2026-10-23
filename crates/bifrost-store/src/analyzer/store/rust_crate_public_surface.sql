-- Only the current frontier's selected public bindings enter the graph. The
-- foreign branch is tied to the exact topology selected for this wave.
INSERT OR IGNORE INTO cr_surface_bindings
SELECT selected.crate_key, selected.module_path, selected.namespace, selected.name,
       selected.origin,
       selected.namespace = 'type' AND EXISTS (
         SELECT 1 FROM source_native_declaration_bridges AS bridge
         CROSS JOIN source_rust_declaration_properties AS properties
           ON properties.blob_id = bridge.blob_id
          AND properties.declaration_id = bridge.declaration_id
         WHERE bridge.blob_id = selected.declaration_blob_id
           AND bridge.source_site = selected.declaration_site
           AND properties.declaration_kind IN (1, 4, 5))
FROM (
  SELECT exports.*
  FROM cr_surface_frontier AS frontier
  CROSS JOIN cr_exports AS exports
    ON exports.crate_key = frontier.crate_key
   AND exports.module_path = frontier.module_path
  WHERE exports.crate_key = (SELECT crate_key FROM cr_identity)
    AND exports.visibility = 'public'
  UNION ALL
  SELECT frontier.crate_key, exports.module_path, exports.namespace, exports.name,
         exports.origin, exports.visibility, exports.restricted_module_path,
         exports.declaration_blob_id, exports.declaration_site
  FROM cr_surface_frontier AS frontier
  CROSS JOIN cr_foreign AS foreign_crate ON foreign_crate.crate_key = frontier.crate_key
  CROSS JOIN rust_crate_exports AS exports
    ON exports.topology_id = foreign_crate.topology_id
   AND exports.module_path = frontier.module_path
  WHERE exports.visibility = 'public'
) AS selected;
