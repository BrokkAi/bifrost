-- A reachable open inventory cannot prove an empty complete surface, even
-- when its presently known bindings are empty. Read only the reached module.
INSERT OR IGNORE INTO cr_surface_facts
SELECT 'public_module_inventory_unavailable', frontier.crate_key, frontier.module_path,
       '', '', X'', ''
FROM cr_surface_frontier AS frontier
WHERE frontier.crate_key = (SELECT crate_key FROM cr_identity)
  AND EXISTS (SELECT 1 FROM cr_gaps AS gap
               WHERE gap.gap_kind = 'open_export_inventory'
                 AND gap.subject = frontier.module_path)
UNION ALL
SELECT 'public_module_inventory_unavailable', frontier.crate_key, frontier.module_path,
       '', '', X'', ''
FROM cr_surface_frontier AS frontier
CROSS JOIN cr_foreign AS foreign_crate ON foreign_crate.crate_key = frontier.crate_key
WHERE EXISTS (SELECT 1 FROM rust_crate_gaps AS gap
               WHERE gap.topology_id = foreign_crate.topology_id
                 AND gap.gap_kind = 'open_export_inventory'
                 AND gap.subject = frontier.module_path);
