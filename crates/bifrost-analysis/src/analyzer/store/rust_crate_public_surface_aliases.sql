-- Shared alias projection for module frontiers and keyed glob requests.
-- A crate-root/self alias need not have a declaration-backed export row.
-- Other named aliases enter here only when the existing route closure proves
-- that they name a container. An existing type winner always shadows them.
INSERT OR IGNORE INTO {output}
SELECT {owner_columns}demand.crate_key, routes.module_path, routes.bound_name{origin_column}
FROM {frontier} AS demand
CROSS JOIN cr_reexports AS routes ON routes.module_path = demand.module_path {name_predicate}
WHERE demand.crate_key = (SELECT crate_key FROM cr_identity)
  AND routes.visibility = 'public'
  AND NOT EXISTS (SELECT 1 FROM cr_exports AS selected
                  WHERE selected.crate_key = demand.crate_key
                    AND selected.module_path = routes.module_path
                    AND selected.namespace = 'type' AND selected.name = routes.bound_name)
  AND (routes.target_name = 'self' OR EXISTS (
    SELECT 1 FROM cr_reexport_closure AS named
    CROSS JOIN cr_containers_all AS target
      ON target.crate_key = named.target_crate_key
     AND target.container_path = named.target_container_path
    WHERE named.crate_key = demand.crate_key AND named.module_path = routes.module_path
      AND named.bound_name = routes.bound_name))
UNION ALL
SELECT {owner_columns}demand.crate_key, routes.module_path, routes.bound_name{origin_column}
FROM {frontier} AS demand
CROSS JOIN cr_foreign AS foreign_crate ON foreign_crate.crate_key = demand.crate_key
CROSS JOIN rust_crate_reexport_routes AS routes
  ON routes.topology_id = foreign_crate.topology_id
 AND routes.module_path = demand.module_path {name_predicate}
WHERE routes.visibility = 'public'
  AND NOT EXISTS (SELECT 1 FROM rust_crate_exports AS selected
                  WHERE selected.topology_id = foreign_crate.topology_id
                    AND selected.module_path = routes.module_path
                    AND selected.namespace = 'type' AND selected.name = routes.bound_name)
  AND (routes.target_name = 'self' OR EXISTS (
    SELECT 1 FROM cr_reexport_closure AS named
    CROSS JOIN cr_containers_all AS target
      ON target.crate_key = named.target_crate_key
     AND target.container_path = named.target_container_path
    WHERE named.crate_key = demand.crate_key AND named.module_path = routes.module_path
      AND named.bound_name = routes.bound_name));
