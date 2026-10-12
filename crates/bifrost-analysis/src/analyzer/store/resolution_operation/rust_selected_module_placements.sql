-- Relate selected module ancestry to the selected crate placement. Local
-- ordinals are blob-owned and must never be carried across content changes.
CREATE TEMP VIEW IF NOT EXISTS selected_rust_module_placements AS
SELECT mount.mount_ordinal, mount.blob_id, scope.ordinal AS scope_ordinal,
       scope.declaration_id AS module_declaration, owner.topology_id,
       owner.unit_key, members.summary_id, members.member_ordinal,
       placement.module_path AS container_path, members.blob_id AS placement_blob
FROM selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=mount.blob_id
CROSS JOIN selected_workspace_file_versions AS file
 ON file.lang=mount.storage_language AND file.rel_path=mount.persisted_relative_path
CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
CROSS JOIN main.resolution_unit_summary_members AS members
 INDEXED BY resolution_unit_summary_members_blob
 ON members.blob_id=base.id AND members.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=members.summary_id
CROSS JOIN main.rust_resolution_unit_summary_placements AS placement
 INDEXED BY rust_resolution_unit_summary_placements_member
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
