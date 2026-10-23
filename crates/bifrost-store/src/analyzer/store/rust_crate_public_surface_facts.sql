-- Tags and canonical coordinates are output identity. Declaration evidence,
-- row IDs, topology IDs, and consumed dependency digests never enter it.
INSERT OR IGNORE INTO cr_surface_facts
SELECT 'public_module_node', crate_key, module_path, '', '', X'', ''
FROM cr_surface_frontier
UNION ALL
SELECT 'public_module_binding', crate_key, module_path, namespace, name, X'', ''
FROM cr_surface_bindings
UNION ALL
SELECT 'public_module_edge', crate_key, module_path, 'type', name,
       target_crate_key, target_module_path
FROM cr_surface_candidates
UNION ALL
SELECT 'public_module_ambiguous', module.crate_key, module.module_path, 'type', module.name, X'', ''
FROM cr_surface_candidates AS module
GROUP BY module.crate_key, module.module_path, module.name
HAVING count(*) > 1 OR EXISTS (
  -- Pruning removed only the module's own terminal. Remaining type terminals
  -- are distinct competing targets, even if there is only one module edge.
  SELECT 1 FROM cr_surface_facts AS terminal
  WHERE terminal.kind = 'public_module_terminal'
    AND terminal.crate_key = module.crate_key
    AND terminal.module_path = module.module_path
    AND terminal.namespace = 'type' AND terminal.name = module.name)
UNION ALL
SELECT 'public_module_unavailable', binding.crate_key, binding.module_path,
       binding.namespace, binding.name, X'', ''
FROM cr_surface_bindings AS binding
WHERE binding.module_expected = 1
  AND NOT EXISTS (SELECT 1 FROM cr_surface_candidates AS candidate
                  WHERE candidate.crate_key = binding.crate_key
                    AND candidate.module_path = binding.module_path
                    AND candidate.name = binding.name);
