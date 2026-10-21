-- Uncertainty belongs to the surface projection. Preserve every candidate
-- edge for change sensitivity while leaving legacy resolution winners alone.
INSERT INTO cr_gaps
SELECT 'open_export_inventory',
       'public-module-surface:' || hex(fact.crate_key) || ':' || fact.module_path
         || ':' || fact.namespace || ':' || fact.name,
       json_object('subject_level', 'public_surface', 'reason', fact.kind, 'crate_key', hex(fact.crate_key),
                   'module_path', fact.module_path, 'namespace', fact.namespace,
                   'name', fact.name,
                   'candidates', json((
                     SELECT json_group_array(json_object('crate_key', hex(edge.target_crate_key),
                                                         'module_path', edge.target_module_path))
                     FROM cr_surface_facts AS edge
                     WHERE edge.kind IN ('public_module_edge', 'public_module_terminal')
                       AND edge.crate_key = fact.crate_key
                       AND edge.module_path = fact.module_path
                       AND edge.namespace = fact.namespace AND edge.name = fact.name)))
FROM cr_surface_facts AS fact
WHERE fact.kind IN ('public_module_ambiguous', 'public_module_unavailable',
                    'public_module_inventory_unavailable');
