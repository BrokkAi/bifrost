-- Namespaces and canonical terminal names matter even when no module edge
-- follows. A public Event re-export can change its declaration while keeping
-- the Event spelling. The named closure also handles private intermediate
-- aliases; its terminal coordinate is a semantic path, not source text.
INSERT OR IGNORE INTO cr_surface_facts
SELECT 'public_module_terminal', selected.owner_crate_key, selected.owner_module_path,
       selected.owner_namespace, selected.owner_name,
       selected.crate_key, selected.module_path || '::' || selected.name
FROM cr_surface_lookup AS selected
WHERE selected.origin = 'declaration'
UNION ALL
SELECT 'public_module_named_terminal', selected.owner_crate_key, selected.owner_module_path,
       selected.owner_namespace, selected.owner_name,
       named.target_crate_key, named.target_container_path
FROM cr_surface_lookup AS selected
CROSS JOIN cr_reexport_closure AS named
  ON named.crate_key = selected.crate_key AND named.module_path = selected.module_path
 AND named.bound_name = selected.name
WHERE selected.origin = 'reexport';
