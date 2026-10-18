-- Follow direct public glob routes only for a reached selected glob key.
-- The next iteration selects that same namespace/name in the destination before
-- any further route is considered, preserving named/declaration shadowing
-- at every hop. The request primary key terminates glob cycles and diamonds.
INSERT OR IGNORE INTO cr_surface_requests
SELECT selected.owner_crate_key, selected.owner_module_path, selected.owner_namespace, selected.owner_name,
       routes.target_crate_key, routes.target_module_path, selected.name, 0
FROM cr_surface_lookup AS selected
CROSS JOIN cr_glob_reexports AS routes ON routes.module_path = selected.module_path
WHERE selected.crate_key = (SELECT crate_key FROM cr_identity)
  AND selected.origin = 'glob_reexport' AND routes.visibility = 'public'
UNION ALL
SELECT selected.owner_crate_key, selected.owner_module_path, selected.owner_namespace, selected.owner_name,
       routes.target_crate_key, routes.target_module_path, selected.name, 0
FROM cr_surface_lookup AS selected
CROSS JOIN cr_foreign AS foreign_crate ON foreign_crate.crate_key = selected.crate_key
CROSS JOIN rust_crate_glob_reexport_routes AS routes
  ON routes.topology_id = foreign_crate.topology_id
 AND routes.module_path = selected.module_path
WHERE selected.origin = 'glob_reexport' AND routes.visibility = 'public';
