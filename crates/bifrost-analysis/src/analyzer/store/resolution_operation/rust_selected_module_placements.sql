-- Relate selected module ancestry to the selected crate placement. Local
-- ordinals are blob-owned and must never be carried across content changes.
CREATE TEMP VIEW IF NOT EXISTS selected_rust_module_placements AS
SELECT mount.mount_ordinal, mount.blob_id, scope.ordinal AS scope_ordinal,
       scope.declaration_id AS module_declaration, source.topology_id,
       source.container_path, source.blob_id AS placement_blob
FROM selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=mount.blob_id
CROSS JOIN selected_workspace_file_versions AS file
 ON file.lang=mount.storage_language AND file.rel_path=mount.persisted_relative_path
CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
CROSS JOIN rust_crate_container_sources AS source INDEXED BY rust_crate_containers_rel_path
 ON source.blob_id=base.id AND source.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
WHERE mount.storage_language='rust' AND source.scope_ordinal IS NOT NULL
 AND EXISTS (
 WITH RECURSIVE aligned(old_scope,new_scope) AS (
  SELECT source.scope_ordinal,scope.ordinal
  UNION ALL
  SELECT old.parent_ordinal,new.parent_ordinal FROM aligned
  CROSS JOIN source_rust_module_scopes AS old ON old.blob_id=source.blob_id AND old.ordinal=aligned.old_scope
  CROSS JOIN source_rust_module_scopes AS new ON new.blob_id=mount.blob_id AND new.ordinal=aligned.new_scope
  WHERE old.module_name=new.module_name AND old.parent_ordinal IS NOT NULL AND new.parent_ordinal IS NOT NULL
 ) SELECT 1 FROM aligned WHERE old_scope=0 AND new_scope=0
 );
