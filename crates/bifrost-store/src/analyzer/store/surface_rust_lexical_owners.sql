-- Empty-symbol paths give native ancestry. Traverse non-scope nodes until the
-- next structural scope, keeping all candidates rather than selecting a handle.
-- Without sqlite_stat1 the planner prefers the blob_id-only primary key or the
-- end_node range of resolution_paths_reverse for the path steps, which scans
-- every path of the blob once per hop and stalled a cold warm of a large file
-- for hours (#14394). Each hop is a (blob_id, start_node) point lookup, so
-- the path steps are pinned to resolution_paths_forward after their node.
WITH RECURSIVE
hops(blob_id, scope, node) AS (
  SELECT head.blob_id, head.source_scope, path.end_node
  FROM main.resolution_node_catalog AS head
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_forward
    ON path.blob_id=head.blob_id AND path.start_node=head.local_key
  WHERE head.blob_id=?1 AND head.source_scope IS NOT NULL
    AND path.start_lead_identity IS NULL AND path.start_lead_local IS NULL
    AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL AND path.end_node>=0
  UNION
  SELECT hops.blob_id, hops.scope, path.end_node FROM hops
  CROSS JOIN main.resolution_node_catalog AS node ON node.blob_id=hops.blob_id AND node.local_key=hops.node
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_forward
    ON path.blob_id=node.blob_id AND path.start_node=node.local_key
  WHERE node.source_scope IS NULL
    AND path.start_lead_identity IS NULL AND path.start_lead_local IS NULL
    AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL AND path.end_node>=0
), parents AS (
  SELECT DISTINCT hops.blob_id, hops.scope, node.source_scope AS parent_scope
  FROM hops JOIN main.resolution_node_catalog AS node
    ON node.blob_id=hops.blob_id AND node.local_key=hops.node
  WHERE node.source_scope IS NOT NULL AND node.source_scope<>hops.scope
), seeds(blob_id, scope, module_scope) AS (
  SELECT blob_id, resolution_scope, ordinal FROM main.source_rust_module_scopes
  WHERE blob_id=?1 AND resolution_scope IS NOT NULL
  UNION
  SELECT blob_id, owner_scope, module_scope FROM temp.surface_rust_declaration_owners_source
  WHERE blob_id=?1 AND owner_scope IS NOT NULL
  UNION
  SELECT blob_id, owner_scope, module_scope FROM temp.surface_rust_import_owners_source
  WHERE blob_id=?1 AND owner_scope IS NOT NULL
), owners(blob_id, scope, module_scope) AS (
  SELECT * FROM seeds
  UNION
  SELECT owners.blob_id, parents.parent_scope, owners.module_scope FROM owners
  JOIN parents ON parents.blob_id=owners.blob_id AND parents.scope=owners.scope
  JOIN main.source_rust_module_scopes AS module
    ON module.blob_id=owners.blob_id AND module.ordinal=owners.module_scope
  WHERE owners.scope IS NOT module.resolution_scope
)
SELECT DISTINCT owners.blob_id, owners.scope,
       CASE WHEN owners.scope IS module.resolution_scope THEN NULL ELSE parents.parent_scope END AS parent_scope,
       owners.module_scope,
       EXISTS(SELECT 1 FROM main.resolution_member_scope_properties AS body
              JOIN main.resolution_node_catalog AS head
                ON head.blob_id=body.blob_id AND head.local_key=body.scope_head_node_key
              WHERE head.blob_id=owners.blob_id AND head.source_scope=owners.scope) AS member_body
FROM owners
JOIN main.source_rust_module_scopes AS module
  ON module.blob_id=owners.blob_id AND module.ordinal=owners.module_scope
LEFT JOIN parents ON parents.blob_id=owners.blob_id AND parents.scope=owners.scope
