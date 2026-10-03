-- Every reference in a member blob that routes through the crate root, placed
-- in the module whose body contains it. The tier-1 root-route family carries
-- the route's terminal name and the reference site that demands it, so this
-- reads one relation per member blob instead of joining path bodies.
INSERT INTO cr_root_sources
SELECT members.blob_id, route.path_key, members.module_path,
       route.terminal_spelling, route.reference_source_site
FROM cr_members AS members
CROSS JOIN resolution_root_route_segments AS route
  ON route.blob_id=members.blob_id AND route.terminal_spelling IS NOT NULL
WHERE route.reference_start_byte >= members.start_byte
  AND route.reference_end_byte <= members.end_byte
  AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module WHERE inner_module.blob_id=members.blob_id
      AND inner_module.scope_ordinal<>members.scope_ordinal
      AND inner_module.start_byte>=members.start_byte AND inner_module.end_byte<=members.end_byte
      AND route.reference_start_byte>=inner_module.start_byte
      AND route.reference_end_byte<=inner_module.end_byte);
