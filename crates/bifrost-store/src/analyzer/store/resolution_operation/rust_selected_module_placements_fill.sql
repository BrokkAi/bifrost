-- Reprove every container against the edited mount before admitting it.
DELETE FROM temp.selected_rust_transient_placement_attributes;
DELETE FROM temp.selected_resolution_transient_placements;
INSERT INTO temp.selected_resolution_transient_placements
SELECT mount.mount_ordinal, members.summary_id, placement.container_path,
       members.member_ordinal, scope.ordinal
FROM selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=mount.blob_id
CROSS JOIN selected_workspace_file_versions AS file
 ON file.lang=mount.storage_language AND file.rel_path=mount.persisted_relative_path
CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
 AND base.parse_variant=x''
CROSS JOIN main.resolution_unit_summary_members AS members
 INDEXED BY resolution_unit_summary_members_blob
 ON members.blob_id=base.id AND members.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=members.summary_id
CROSS JOIN main.resolution_unit_summary_placements AS placement
 INDEXED BY resolution_unit_summary_placements_member
 ON placement.summary_id=members.summary_id
AND placement.member_ordinal=members.member_ordinal
WHERE mount.storage_language='rust' AND placement.scope_ordinal IS NOT NULL
 AND EXISTS (
 WITH RECURSIVE aligned(old_scope,new_scope) AS (
  SELECT placement.scope_ordinal,scope.ordinal
  UNION ALL
  SELECT old.parent_ordinal,new.parent_ordinal FROM aligned
  CROSS JOIN source_rust_module_scopes AS old ON old.blob_id=members.blob_id AND old.ordinal=aligned.old_scope
  CROSS JOIN source_rust_module_scopes AS new ON new.blob_id=mount.blob_id AND new.ordinal=aligned.new_scope
  WHERE old.module_name=new.module_name AND old.parent_ordinal IS NOT NULL AND new.parent_ordinal IS NOT NULL
 ) SELECT 1 FROM aligned WHERE old_scope=0 AND new_scope=0
 );

INSERT INTO temp.selected_rust_transient_placement_attributes
 SELECT p.mount_ordinal, p.summary_id, p.container_path, p.member_ordinal, p.scope_ordinal, scope.declaration_id
 FROM selected_resolution_transient_placements AS p
 JOIN selected_resolution_mounts AS mount ON mount.mount_ordinal=p.mount_ordinal
 JOIN source_rust_module_scopes AS scope
   ON scope.blob_id=mount.blob_id AND scope.ordinal=p.scope_ordinal;
