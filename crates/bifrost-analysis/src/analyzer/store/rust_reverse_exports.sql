-- One definition, including every selected named and glob re-export route.
-- Keep the seed predicate inside the recursive relation: filtering the general
-- reachable view after expansion would enumerate unrelated export inventories.
WITH RECURSIVE exposed(topology_id, crate_key, module_path, namespace, name,
                       visibility, depth) AS (
  SELECT exports.topology_id, owner.crate_key, exports.module_path,
         exports.namespace, exports.name, exports.visibility, 0
  FROM rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration
  CROSS JOIN selected_rust_crates AS owner
    ON owner.topology_id = exports.topology_id
  WHERE exports.declaration_blob_id = ?1 AND exports.declaration_site = ?2
  UNION
  SELECT routes.topology_id, owner.crate_key, routes.module_path,
         target.namespace, routes.bound_name, routes.visibility, target.depth + 1
  FROM exposed AS target
  CROSS JOIN rust_crate_reexport_routes AS routes
    INDEXED BY rust_crate_reexport_routes_target
    ON routes.target_crate_key = target.crate_key
   AND routes.target_module_path = target.module_path
   AND routes.target_name = target.name
  CROSS JOIN selected_rust_crates AS owner ON owner.topology_id = routes.topology_id
  WHERE target.visibility <> 'private'
    AND (target.visibility = 'public' OR target.crate_key = owner.crate_key)
    AND target.depth < 64
  UNION
  SELECT routes.topology_id, owner.crate_key, routes.module_path,
         target.namespace, target.name, routes.visibility, target.depth + 1
  FROM exposed AS target
  CROSS JOIN rust_crate_glob_reexport_routes AS routes
    INDEXED BY rust_crate_glob_reexport_routes_target
    ON routes.target_crate_key = target.crate_key
   AND routes.target_module_path = target.module_path
  CROSS JOIN selected_rust_crates AS owner ON owner.topology_id = routes.topology_id
  WHERE target.visibility <> 'private'
    AND (target.visibility = 'public' OR target.crate_key = owner.crate_key)
    AND target.depth < 64
)
SELECT topology_id, crate_key, module_path, namespace, name, visibility, depth
FROM exposed;
