-- A parsed macro interior is not proof of replay. The native frontier records
-- whether the producer admitted the expansion's facts.
--
-- The persisted lowering discharges that frontier for exactly one kind of
-- invocation: a same-file macro whose every rule expands to its arguments and
-- nothing else. Its items are declared, bridged and exported like any other
-- item, so it leaves no frontier and opens nothing here.
--
-- Every other decided invocation (`cr_item_macro_decisions`) has its items
-- declared by the crate instead (`rust_crate_macro_items.sql`), with the
-- activation its decoration and each item's own `cfg` give them.
-- `rust_crate_macro_item_coverage.sql` records the ones every item of which is
-- accounted for: declared, inactive, or a member of an `impl` or trait body.
-- Those open nothing here either. A decided invocation that is not covered
-- (an item of unknown activation, a `use`, a nested invocation, a
-- `macro_rules!`, a syntax error) keeps the inventory open with `decided`
-- true. An undecided invocation keeps it open with `decided` false when no
-- source fact proves that it has no item route. Unqualified invocations with
-- no native gap and no passthrough route, and unqualified names proven
-- unavailable by local scope, are recorded in `cr_item_macro_no_routes` and
-- open no inventory. One exception: an invocation whose frontier is an
-- unexpanded impl macro (`?1`, the `UnexpandedImplMacro` gap origin code) is
-- proven to write only `impl` blocks, which bind no name in the module, so
-- its frontier opens member surfaces and not this inventory.
--
-- A covered invocation's items are declared against the invoking file's
-- persisted blob. When a request edits that file, the point route's
-- inventory read (`rust_crate_point_inventory.sql`) reopens the module.
INSERT INTO cr_gaps
SELECT 'open_export_inventory', member.module_path,
       json_object('member_blob', member.blob_id,
                   'invocation_occurrence', invocation.invocation_occurrence_id,
                   'macro', (SELECT head.macro_name FROM source_rust_macro_invocations AS head
                             WHERE head.blob_id=invocation.blob_id
                               AND head.occurrence_id=invocation.invocation_occurrence_id),
                   'reason', 'UnsupportedMacroGeneratedModule',
                   'replay_covered', json('false'),
                   'decided', json(CASE WHEN EXISTS (
                       SELECT 1 FROM cr_item_macro_decisions AS decision
                       WHERE decision.blob_id=invocation.blob_id
                         AND decision.invocation_occurrence_id=invocation.invocation_occurrence_id)
                     THEN 'true' ELSE 'false' END))
FROM cr_members AS member
CROSS JOIN source_rust_item_macro_expansions AS invocation
 ON invocation.blob_id=member.blob_id AND invocation.source_position IN (0,1)
LEFT JOIN source_rust_macro_inputs AS input
 ON input.blob_id=invocation.blob_id
 AND input.invocation_occurrence_id=invocation.invocation_occurrence_id
WHERE invocation.invocation_start_byte >= member.start_byte AND invocation.invocation_end_byte <= member.end_byte
 AND NOT EXISTS (SELECT 1 FROM cr_item_macro_no_routes AS no_route
                 WHERE no_route.blob_id=invocation.blob_id
                   AND no_route.invocation_occurrence_id=invocation.invocation_occurrence_id)
 AND CASE WHEN EXISTS (SELECT 1 FROM cr_item_macro_decisions AS decision
                       WHERE decision.blob_id=invocation.blob_id
                       AND decision.invocation_occurrence_id=invocation.invocation_occurrence_id)
      -- Decided: open only when replay parsed items the persisted lowering
      -- left behind its frontier and the crate did not account for all of
      -- them. An empty expansion declares nothing.
      THEN invocation.expansion_kind = 0 AND input.native_gap_site IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM cr_macro_item_covered AS covered
                           WHERE covered.blob_id=invocation.blob_id
                           AND covered.invocation_occurrence_id=invocation.invocation_occurrence_id)
      ELSE (input.native_gap_site IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM resolution_gap_reasons AS frontier
                            WHERE frontier.blob_id=input.blob_id
                              AND frontier.site=input.native_gap_site
                              AND frontier.origin=?1))
           OR invocation.expansion_kind <> 0
     END
 AND NOT EXISTS (SELECT 1 FROM cr_scopes AS inner_module
                 WHERE inner_module.blob_id=member.blob_id
                 AND inner_module.scope_ordinal<>member.scope_ordinal
                 AND inner_module.start_byte>=member.start_byte
                 AND inner_module.end_byte<=member.end_byte
                 AND invocation.invocation_start_byte>=inner_module.start_byte
                 AND invocation.invocation_end_byte<=inner_module.end_byte)
UNION ALL
-- An inline module written inside a decided invocation (`plain! { pub mod m
-- { .. } }`) is placed by the module walk and holds the invocation's items
-- that the expansion writes in its body. Its own inventory is open while the
-- invocation is not accounted for, for the same reason the module holding the
-- invocation is: an item the crate did not declare may be in it. The rule
-- above cannot see it, because the invocation encloses this module rather
-- than lying in it.
SELECT 'open_export_inventory', member.module_path,
       json_object('member_blob', member.blob_id,
                   'invocation_occurrence', invocation.invocation_occurrence_id,
                   'macro', (SELECT head.macro_name FROM source_rust_macro_invocations AS head
                             WHERE head.blob_id=invocation.blob_id
                               AND head.occurrence_id=invocation.invocation_occurrence_id),
                   'reason', 'UnsupportedMacroGeneratedModule',
                   'replay_covered', json('false'),
                   'decided', json('true'))
FROM cr_members AS member
CROSS JOIN source_rust_module_scopes AS scope
 ON scope.blob_id=member.blob_id AND scope.ordinal=member.scope_ordinal
CROSS JOIN source_declarations AS placed
 ON placed.blob_id=scope.blob_id AND placed.declaration_id=scope.declaration_id
CROSS JOIN source_rust_item_macro_expansions AS invocation
 ON invocation.blob_id=member.blob_id
 AND invocation.invocation_start_byte<=placed.start_byte
 AND placed.end_byte<=invocation.invocation_end_byte
CROSS JOIN source_rust_macro_inputs AS input
 ON input.blob_id=invocation.blob_id
 AND input.invocation_occurrence_id=invocation.invocation_occurrence_id
WHERE invocation.expansion_kind = 0 AND input.native_gap_site IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM cr_item_macro_no_routes AS no_route
                 WHERE no_route.blob_id=invocation.blob_id
                   AND no_route.invocation_occurrence_id=invocation.invocation_occurrence_id)
 AND EXISTS (SELECT 1 FROM cr_item_macro_decisions AS decision
             WHERE decision.blob_id=invocation.blob_id
               AND decision.invocation_occurrence_id=invocation.invocation_occurrence_id)
 AND NOT EXISTS (SELECT 1 FROM cr_macro_item_covered AS covered
                 WHERE covered.blob_id=invocation.blob_id
                   AND covered.invocation_occurrence_id=invocation.invocation_occurrence_id)
UNION ALL
-- An active module-level declaration whose file's lowering produced no
-- definition for it: the producer withheld the item, for one because an
-- attribute on it might be an attribute macro that replaces it. No export row
-- names it, so without this row the module's inventory looked closed and a
-- lookup of the name answered a proved absence. An item written inside an
-- item-macro invocation is excluded: the crate declares it through
-- `rust_crate_macro_items`, and the invocation arms above decide whether it
-- opens the module.
SELECT 'open_export_inventory', candidate.module_path,
       json_object('member_blob', candidate.blob_id,
                   'declaration_id', candidate.declaration_id,
                   'reason', 'UnloweredDeclaration')
FROM cr_source_declarations AS candidate
WHERE candidate.nearest_declaration_boundary = 0
  AND candidate.declaration_kind NOT IN (8, 9, 14)
  AND candidate.activation = 1
  AND NOT EXISTS (SELECT 1 FROM source_native_declaration_bridges AS bridges
                  CROSS JOIN resolution_semantic_sites AS sites
                   ON sites.blob_id = bridges.blob_id AND sites.source_site = bridges.source_site
                   AND sites.semantic_role = 'definition'
                  WHERE bridges.blob_id = candidate.blob_id
                    AND bridges.declaration_id = candidate.declaration_id)
  AND NOT EXISTS (SELECT 1 FROM source_declarations AS declaration
                  CROSS JOIN source_rust_item_macro_expansions AS invocation
                   ON invocation.blob_id = declaration.blob_id
                   AND invocation.invocation_start_byte <= declaration.start_byte
                   AND declaration.end_byte <= invocation.invocation_end_byte
                  WHERE declaration.blob_id = candidate.blob_id
                    AND declaration.declaration_id = candidate.declaration_id);
