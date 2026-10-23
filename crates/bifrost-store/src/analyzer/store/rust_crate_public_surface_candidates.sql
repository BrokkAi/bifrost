-- Reuse the module walk's physical-container and canonical named-closure
-- interpretation. The selected origin controls precedence: a named winner
-- cannot expand shadowed globs, and only an actual declaration names a
-- physical child here. Both helpers contain only local or exact-wave targets.
INSERT OR IGNORE INTO cr_surface_candidates
SELECT selected.owner_crate_key, selected.owner_module_path, selected.owner_name,
       child.crate_key, child.container_path
FROM cr_surface_lookup AS selected
CROSS JOIN cr_containers_all AS child
  ON child.crate_key = selected.crate_key
 AND child.container_path = selected.module_path || '::' || selected.name
WHERE selected.owner_namespace = 'type' AND selected.origin = 'declaration'
UNION ALL
SELECT selected.owner_crate_key, selected.owner_module_path, selected.owner_name,
       target.crate_key, target.container_path
FROM cr_surface_lookup AS selected
CROSS JOIN cr_reexport_closure AS named
  ON named.crate_key = selected.crate_key AND named.module_path = selected.module_path
 AND named.bound_name = selected.name
CROSS JOIN cr_containers_all AS target
  ON target.crate_key = named.target_crate_key
 AND target.container_path = named.target_container_path
WHERE selected.owner_namespace = 'type' AND selected.origin = 'reexport';
