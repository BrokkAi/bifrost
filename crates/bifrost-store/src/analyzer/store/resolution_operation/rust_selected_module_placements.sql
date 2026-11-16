CREATE TEMP TABLE IF NOT EXISTS selected_rust_transient_placement_attributes (
 mount_ordinal INTEGER NOT NULL,
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
 module_declaration INTEGER,
 PRIMARY KEY(mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal)
) WITHOUT ROWID, STRICT;
-- PLACEMENTS and REFERENCE_PLACEMENTS seek a selected module declaration.
CREATE INDEX IF NOT EXISTS temp.selected_rust_transient_placement_attributes_declaration
 ON selected_rust_transient_placement_attributes(module_declaration, summary_id, container_path, member_ordinal, mount_ordinal, scope_ordinal);
-- Every reader goes through this view. It is one SELECT, not a UNION ALL of the
-- changed and the unchanged placements: SQLite materializes a compound view
-- whole when the reading query is DISTINCT or a recursive step, and that would
-- read every unchanged mount. The candidates are the persisted placements of the
-- members at each mount's path; `scope.ordinal IN (...)` names the scopes of the
-- mount's blob that each placement holds, by one of two arms.
--  - A mount whose selected blob is the persisted blob of its member (the
--    placement blob; the fill's `base.id<>mount.blob_id` negated) holds the
--    persisted scope of the placement and every same-named sibling scope of that
--    blob: the sibling scopes the walk persisted as the inactive placements of
--    the same module path and file (cfg alternatives, activation 0, and macro
--    gated copies, activation -1). They are read by a keyed seek of
--    rust_resolution_unit_summary_inactive_placements on
--    (summary_id, module_path, input_file_ordinal), with no alignment recursion
--    and nothing filled per request.
--  - A changed mount (overlay replacement) was aligned against the persisted
--    blob by the fill into selected_resolution_transient_placements, which holds
--    only these mounts; the scopes are that mount's rows for the placement.
-- Both exclude the unplaced set.
CREATE TEMP VIEW IF NOT EXISTS selected_rust_container_placements AS
 SELECT mount.mount_ordinal, mount.blob_id, scope.ordinal AS scope_ordinal,
        scope.declaration_id AS module_declaration, owner.topology_id, owner.unit_key,
        placement.summary_id, placement.member_ordinal,
        CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END AS container_path,
        member.blob_id AS placement_blob
 FROM selected_resolution_mounts AS mount
 JOIN temp.selected_unit_member_blobs AS member
   ON member.rel_path=mount.persisted_relative_path
 JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=member.summary_id
 JOIN main.resolution_unit_summary_placements AS placement
   ON placement.summary_id=member.summary_id AND placement.member_ordinal=member.member_ordinal
 JOIN source_rust_module_scopes AS scope
   ON scope.blob_id=mount.blob_id AND scope.ordinal IN (
    SELECT persisted.dense_id FROM temp.surface_dense AS persisted
    WHERE member.blob_id=mount.blob_id
      AND persisted.blob_id=mount.blob_id AND persisted.id_space=7
      AND persisted.surface_ordinal=placement.scope_surface_ordinal
    UNION ALL
    -- The only role the unit summaries give an input file is 'inactive_source'
    -- (UnitSummaryInputRole); it completes the unique key of the input file.
    SELECT sibling.dense_id FROM main.resolution_unit_summary_input_files AS input
    JOIN main.rust_resolution_unit_summary_inactive_placements AS inactive
      ON inactive.summary_id=input.summary_id AND inactive.input_file_ordinal=input.input_ordinal
     AND inactive.module_path=CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END
    JOIN temp.surface_dense AS sibling
      ON sibling.blob_id=mount.blob_id AND sibling.id_space=7
     AND sibling.surface_ordinal=inactive.module_scope_surface_ordinal
    WHERE member.blob_id=mount.blob_id
      AND input.summary_id=placement.summary_id AND input.source_role='inactive_source'
      AND input.rel_path=mount.persisted_relative_path
    UNION ALL
    SELECT changed.scope_ordinal FROM temp.selected_resolution_transient_placements AS changed
    WHERE member.blob_id<>mount.blob_id
      AND changed.mount_ordinal=mount.mount_ordinal AND changed.summary_id=placement.summary_id
      AND changed.container_path=placement.container_path AND changed.member_ordinal=placement.member_ordinal)
 WHERE mount.storage_language='rust' AND placement.scope_surface_ordinal IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM temp.selected_rust_unplaced_placements AS unplaced
                   WHERE unplaced.summary_id=placement.summary_id
                     AND unplaced.container_path=placement.container_path
                     AND unplaced.member_ordinal=placement.member_ordinal);
