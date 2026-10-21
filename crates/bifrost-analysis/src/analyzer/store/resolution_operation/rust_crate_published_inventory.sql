-- A closed own owner does not close the inherited macro-use prelude. An own
-- certificate shadows this fallback, including a listed empty certificate.
, inventory_owners AS (
 SELECT owner_id,topology_id,module_path,closed FROM published_owners
 UNION
 SELECT provider.owner_id,owner.topology_id,owner.module_path,owner.closed
 FROM macro_prelude_owners provider
 CROSS JOIN rust_crate_binding_owners owner ON owner.owner_id=provider.owner_id
 WHERE NOT EXISTS(SELECT 1 FROM published_owners own
 CROSS JOIN rust_crate_binding_names certificate ON certificate.owner_id=own.owner_id
 AND certificate.namespace=?3 AND certificate.name=?4)
), blockers AS (
 SELECT blocker.*,owner.topology_id,owner.module_path
 FROM inventory_owners owner CROSS JOIN rust_crate_binding_blockers blocker USING(owner_id)
 WHERE blocker.namespace=?3 AND (blocker.name=?4 OR (blocker.name='' AND NOT EXISTS(
 SELECT 1 FROM rust_crate_binding_names certificate WHERE certificate.owner_id=owner.owner_id
 AND certificate.namespace=?3 AND certificate.name=?4 AND certificate.complete=1)))
), subjects(topology_id,module_path,name) AS (
 SELECT topology_id,module_path,?4 FROM blockers
 UNION
 SELECT unit.topology_id,blocker.evidence_module_path,?4 FROM blockers blocker
 JOIN selected_rust_unit_summaries unit ON unit.unit_key=blocker.evidence_crate_key
 WHERE blocker.name=''
), details AS (
SELECT CASE WHEN EXISTS(SELECT 1 FROM json_each(gap.detail,'$.evidence') scoped
 WHERE json_extract(scoped.value,'$.reason') IN ('InconsistentPrecedence','CyclicExpansion','OpenBoundary'))
 THEN json_object('evidence',json_group_array(json(evidence.value) ORDER BY evidence.value)) ELSE json(gap.detail) END FROM subjects AS targets
 CROSS JOIN selected_rust_unit_summaries AS unit ON unit.topology_id=targets.topology_id
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
 ON gap.summary_id=unit.summary_id
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility','unplaced_module','duplicate_placement')
 AND gap.subject IN (targets.module_path, targets.module_path || '::' || targets.name)
 CROSS JOIN json_each(gap.detail,'$.evidence') AS evidence
 WHERE (json_extract(evidence.value,'$.namespace') IS NULL
        OR ?3='' OR json_extract(evidence.value,'$.namespace')=?3)
 AND (json_extract(evidence.value,'$.binder_scope') IS NULL
      OR json_extract(evidence.value,'$.member_blob')=0)
 -- A scoped row is an obligation for this exact binding, never a module
 -- inventory. The parent's binding of this module name can share the module's
 -- rendered gap subject; it must not open names inside the module.
 AND (json_type(evidence.value,'$.binder_scope') IS NULL
      OR (gap.subject=targets.module_path || '::' || targets.name
          AND json_extract(evidence.value,'$.member_blob')=0
          AND json_extract(evidence.value,'$.binder_scope')=0
          AND json_extract(evidence.value,'$.reason') NOT IN
            ('InconsistentPrecedence','UnsupportedGlobConflictVisibility')))
 GROUP BY gap.summary_id,gap.gap_kind,gap.subject
UNION ALL
-- The crate declared the items of a module's decided item-macro invocations
-- against the persisted blob of the file that invokes them, and closed the
-- module's inventory on that account (`rust_crate_macro_item_coverage.sql`).
-- A request that edits that file reads other content: its invocations have no
-- crate rows, so the module is open for this request. The persisted file's
-- invocations left behind its frontier are the ones the crate accounted for.
SELECT json_object('evidence', json_array(json_object(
         'member_blob', member.blob_id, 'selected_blob', mount.blob_id,
         'reason', 'EditedMacroHost')))
FROM targets
CROSS JOIN selected_rust_unit_summaries AS unit ON unit.topology_id=targets.topology_id
CROSS JOIN main.rust_unit_summary_placements AS source
 ON source.summary_id=unit.summary_id AND source.module_path=targets.module_path
CROSS JOIN main.resolution_unit_summary_members AS member
 ON member.summary_id=source.summary_id AND member.member_ordinal=source.member_ordinal
CROSS JOIN temp.selected_resolution_mounts AS mount
 ON mount.storage_language='rust' AND mount.persisted_relative_path=member.rel_path
 AND mount.blob_id<>member.blob_id
WHERE EXISTS (SELECT 1 FROM source_rust_item_macro_expansions AS invocation
              CROSS JOIN source_rust_macro_inputs AS input
               ON input.blob_id=invocation.blob_id
               AND input.invocation_occurrence_id=invocation.invocation_occurrence_id
              WHERE invocation.blob_id=member.blob_id AND invocation.source_position IN (0,1)
                AND invocation.expansion_kind=0 AND input.native_gap_site IS NOT NULL)

) SELECT DISTINCT * FROM details ORDER BY 1
