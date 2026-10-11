-- Continues `rust_crate_point_targets.sql`. An unindexed external glob can
-- bind any macro name in the module where it is active, and a macro-use
-- extern-crate import contributes macros throughout its crate's prelude.
, unindexed_globs AS (
 SELECT DISTINCT targets.topology_id, source.container_path,
        import.visibility,
        cr_restriction(import.visibility,source.container_path,
          (SELECT parent.container_path FROM rust_crate_container_sources AS parent
           CROSS JOIN source_rust_module_declarations AS declaration
            ON declaration.blob_id=parent.blob_id
           WHERE parent.topology_id=source.topology_id
            AND parent.container_path || '::' || declaration.module_name=source.container_path
           LIMIT 1)) AS restricted_module_path,
        import.cfg_condition, owner.cfg_atoms
 FROM targets
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=targets.topology_id
 AND source.container_path=targets.module_path
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=source.blob_id AND import.native_scope=scope.resolution_scope
 AND import.is_glob=1 AND import.local_start IS NULL
 CROSS JOIN source_rust_import_module_segments AS root
  ON root.blob_id=import.blob_id AND root.import_ordinal=import.ordinal
 AND root.ordinal=0
 CROSS JOIN rust_crate_gaps AS dependency
  ON dependency.topology_id=source.topology_id
 AND dependency.gap_kind='external_dependency'
 AND (dependency.subject=root.segment
  OR (dependency.subject=source.container_path || '::*'
      AND json_extract(dependency.detail,'$.imported_name')=root.segment))
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
 WHERE cr_cfg(import.cfg_condition,json(owner.cfg_atoms))<>0
)
SELECT 1
FROM unindexed_globs
WHERE cr_visibility(visibility)='public'
 OR (topology_id=?5 AND (
  cr_visibility(visibility)='crate'
  OR (cr_visibility(visibility)='private'
      AND (?6=container_path OR substr(?6,1,length(container_path)+2)=container_path || '::'))
  OR (cr_visibility(visibility)='restricted'
      AND (?6=restricted_module_path
       OR substr(?6,1,length(restricted_module_path)+2)=restricted_module_path || '::'))))
UNION
SELECT 1
FROM targets
CROSS JOIN rust_crate_container_sources AS source
 ON source.topology_id=targets.topology_id AND source.container_path='crate'
CROSS JOIN source_rust_module_scopes AS scope
 ON scope.blob_id=source.blob_id AND scope.ordinal=source.scope_ordinal
CROSS JOIN source_rust_import_targets AS import
 ON import.blob_id=source.blob_id AND import.native_scope=scope.resolution_scope
 AND import.is_extern_crate=1 AND import.is_macro_use=1
 AND import.local_start IS NULL
CROSS JOIN rust_crate_gaps AS dependency
 ON dependency.topology_id=source.topology_id
 AND dependency.gap_kind='external_dependency'
 AND (dependency.subject=import.imported_name
  OR (dependency.subject=source.container_path || '::' || COALESCE(import.bound_name,'*')
      AND json_extract(dependency.detail,'$.imported_name')=import.imported_name))
CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
WHERE ?3='macro' AND cr_cfg(import.cfg_condition,json(owner.cfg_atoms))<>0;
