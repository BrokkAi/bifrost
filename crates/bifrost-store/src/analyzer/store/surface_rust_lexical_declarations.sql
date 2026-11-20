-- resolution_identities is global but interned: an id keeps its digest, and a
-- blob's own names are filled by the transaction that publishes that blob, so
-- name.namespace/spelling cannot change under a published blob's fingerprint.
-- Declaration incidence before cfg/name selection, with the path's own identity.
SELECT scope.blob_id, scope.source_scope AS scope, authority.semantic_key,
       name.namespace, name.spelling
FROM main.resolution_node_catalog AS scope
JOIN main.resolution_paths AS path
  ON path.blob_id=scope.blob_id AND path.start_node=scope.local_key
JOIN main.resolution_identities AS name ON name.id=path.start_lead_identity
JOIN main.resolution_node_catalog AS endpoint
  ON endpoint.blob_id=path.blob_id AND endpoint.local_key=path.end_node
JOIN main.resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=endpoint.blob_id AND authority.semantic_key=endpoint.semantic_local_key
WHERE scope.blob_id=?1 AND scope.kind=1 AND scope.source_scope IS NOT NULL
  AND path.root_terminal IS NULL AND path.end_lead_identity IS NULL
  AND path.end_lead_local IS NULL
