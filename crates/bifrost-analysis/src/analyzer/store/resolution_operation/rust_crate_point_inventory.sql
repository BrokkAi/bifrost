SELECT json(gap.detail) FROM targets CROSS JOIN rust_crate_gaps AS gap
 ON gap.topology_id=targets.topology_id
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility','unplaced_module','duplicate_placement')
 AND gap.subject IN (targets.module_path, targets.module_path || '::' || targets.name)
UNION ALL
-- The crate declared the items of a module's decided item-macro invocations
-- against the persisted blob of the file that invokes them, and closed the
-- module's inventory on that account (`rust_crate_macro_item_coverage.sql`).
-- A request that edits that file reads other content: its invocations have no
-- crate rows, so the module is open for this request. The persisted file's
-- invocations left behind its frontier are the ones the crate accounted for.
SELECT json_object('evidence', json_array(json_object(
         'member_blob', source.blob_id, 'selected_blob', mount.blob_id,
         'reason', 'EditedMacroHost')))
FROM targets
CROSS JOIN rust_crate_container_sources AS source
 ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
CROSS JOIN temp.selected_resolution_mounts AS mount
 ON mount.storage_language='rust' AND mount.persisted_relative_path=source.rel_path
 AND mount.blob_id<>source.blob_id
WHERE EXISTS (SELECT 1 FROM source_rust_item_macro_expansions AS invocation
              CROSS JOIN source_rust_macro_inputs AS input
               ON input.blob_id=invocation.blob_id
               AND input.invocation_occurrence_id=invocation.invocation_occurrence_id
              WHERE invocation.blob_id=source.blob_id AND invocation.source_position IN (0,1)
                AND invocation.expansion_kind=0 AND input.native_gap_site IS NOT NULL)
