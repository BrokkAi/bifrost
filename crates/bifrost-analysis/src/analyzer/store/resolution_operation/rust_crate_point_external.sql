-- Continues `rust_crate_point_targets.sql`. Original import identities for a name that is
-- bound by an import whose path leaves the workspace: `pub use std::sync::Arc;`
-- or `pub use ndarray as tract_ndarray;` in a module a glob re-exports. The
-- crate derivation records each such import as an `external_dependency` gap
-- whose subject is the binding module and bound name, and whose evidence names
-- the import's ordinal in that module's source. The import's own visibility
-- decides whether the requesting module ?6 of topology ?5 can see it, by the
-- rule the export lookup applies to a declaration.
SELECT DISTINCT mount.mount_ordinal, json_extract(binding.end_fixed_key,'$[#-2][0]')
 FROM targets
 CROSS JOIN rust_crate_gaps AS gap
  ON gap.topology_id=targets.topology_id AND gap.gap_kind='external_dependency'
  AND gap.subject=targets.module_path || '::' || targets.name
 CROSS JOIN json_each(gap.detail, '$.evidence') AS evidence
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=source.blob_id AND import.ordinal=evidence.value ->> 'import_ordinal'
  AND import.bound_name=targets.name
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.blob_id=import.blob_id AND mount.storage_language='rust'
  AND mount.persisted_relative_path=source.rel_path
 CROSS JOIN resolution_node_catalog AS scope
  ON scope.blob_id=import.blob_id AND scope.source_scope=import.native_scope
 CROSS JOIN resolution_paths AS binding
  ON binding.blob_id=scope.blob_id AND binding.start_node=scope.local_key
  AND binding.end_node=-1 AND binding.end_open_tail=1
 CROSS JOIN resolution_identities AS identity
  ON identity.id=binding.root_terminal AND identity.spelling=import.bound_name
  AND identity.namespace=?7
 WHERE import.visibility='public'
  OR (targets.topology_id=?5 AND (import.visibility='crate'
   OR (import.visibility='private'
       AND (?6=targets.module_path OR substr(?6,1,length(targets.module_path)+2)=targets.module_path || '::'))))
