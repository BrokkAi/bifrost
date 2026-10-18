-- A named terminal may itself be a selected glob binding. Reuse the
-- structured named step's coordinates to demand that exact namespace/name;
-- do not infer a target by parsing the closure's synthetic terminal path.
INSERT OR IGNORE INTO cr_surface_requests
SELECT selected.owner_crate_key, selected.owner_module_path,
       selected.owner_namespace, selected.owner_name,
       named.target_crate_key, named.target_module_path, named.target_name, 0
FROM cr_surface_lookup AS selected
CROSS JOIN cr_reexport_steps AS named
  ON named.crate_key = selected.crate_key AND named.module_path = selected.module_path
 AND named.bound_name = selected.name
WHERE selected.origin = 'reexport' AND named.target_name <> 'self';
