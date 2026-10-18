-- A closure may end on a synthetic name that a selected glob resolves in
-- turn. Prefer the canonical declaration or module candidates once found;
-- alias-route spelling is not published output identity. Keep the closure's
-- terminal coordinate only when it resolves a private intermediate binding
-- that is absent from the public export relation. A module only replaces its
-- own canonical type terminal; a distinct type target competes with it.
DELETE FROM cr_surface_facts AS fact
WHERE fact.kind IN ('public_module_named_terminal', 'public_module_terminal')
  AND ((fact.kind = 'public_module_named_terminal' AND EXISTS (
                SELECT 1 FROM cr_surface_facts AS terminal
                WHERE terminal.kind = 'public_module_terminal'
                  AND terminal.crate_key = fact.crate_key
                  AND terminal.module_path = fact.module_path
                  AND terminal.namespace = fact.namespace AND terminal.name = fact.name))
       OR (fact.namespace = 'type' AND EXISTS (
         SELECT 1 FROM cr_surface_candidates AS module
         WHERE module.crate_key = fact.crate_key AND module.module_path = fact.module_path
           AND module.name = fact.name
           AND module.target_crate_key = fact.target_crate_key
           AND module.target_module_path = fact.target_module_path)));
