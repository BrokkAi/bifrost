-- Continues `rust_crate_point_targets.sql`. An unindexed external glob can
-- bind any macro name in the module where it is active, and a macro-use
-- extern-crate import contributes macros throughout its crate's prelude.
-- Reads the selected unit's summary rows: placements give each module's
-- source member, its scope and its parent module; the unit's gap rows carry
-- the external dependency boundaries; its context carries the cfg atoms.
, unindexed_globs AS (
 SELECT DISTINCT targets.topology_id, source.module_path,
        import.visibility,
        cr_restriction(import.visibility,source.module_path,source.parent_module_path)
          AS restricted_module_path,
        import.cfg_condition, context.cfg_atoms
 FROM targets
 CROSS JOIN selected_rust_unit_summaries AS unit ON unit.topology_id=targets.topology_id
 CROSS JOIN main.rust_resolution_unit_summary_placements AS source
  ON source.summary_id=unit.summary_id AND source.module_path=targets.module_path
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=source.summary_id AND member.member_ordinal=source.member_ordinal
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=member.blob_id AND scope.ordinal=source.scope_ordinal
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=member.blob_id AND import.native_scope=scope.resolution_scope
 AND import.is_glob=1 AND import.local_start IS NULL
 CROSS JOIN source_rust_import_module_segments AS root
  ON root.blob_id=import.blob_id AND root.import_ordinal=import.ordinal
 AND root.ordinal=0
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS dependency
  ON dependency.summary_id=unit.summary_id
 AND dependency.gap_kind='external_dependency'
 AND (dependency.subject=root.segment
  OR (dependency.subject=source.module_path || '::*'
      AND json_extract(dependency.detail,'$.imported_name')=root.segment))
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context ON context.summary_id=unit.summary_id
 WHERE cr_cfg(import.cfg_condition,json(context.cfg_atoms))<>0
)
SELECT 1
FROM unindexed_globs
WHERE cr_visibility(visibility)='public'
 OR (topology_id=?5 AND (
  cr_visibility(visibility)='crate'
  OR (cr_visibility(visibility)='private'
      AND (?6=module_path OR substr(?6,1,length(module_path)+2)=module_path || '::'))
  OR (cr_visibility(visibility)='restricted'
      AND (?6=restricted_module_path
       OR substr(?6,1,length(restricted_module_path)+2)=restricted_module_path || '::'))))
UNION
SELECT 1
FROM targets
CROSS JOIN selected_rust_unit_summaries AS unit ON unit.topology_id=targets.topology_id
CROSS JOIN main.rust_resolution_unit_summary_placements AS source
 ON source.summary_id=unit.summary_id AND source.module_path='crate'
CROSS JOIN main.resolution_unit_summary_members AS member
 ON member.summary_id=source.summary_id AND member.member_ordinal=source.member_ordinal
CROSS JOIN source_rust_module_scopes AS scope
 ON scope.blob_id=member.blob_id AND scope.ordinal=source.scope_ordinal
CROSS JOIN source_rust_import_targets AS import
 ON import.blob_id=member.blob_id AND import.native_scope=scope.resolution_scope
 AND import.is_extern_crate=1 AND import.is_macro_use=1
 AND import.local_start IS NULL
CROSS JOIN main.rust_resolution_unit_summary_gaps AS dependency
 ON dependency.summary_id=unit.summary_id
 AND dependency.gap_kind='external_dependency'
 AND (dependency.subject=import.imported_name
  OR (dependency.subject=source.module_path || '::' || COALESCE(import.bound_name,'*')
      AND json_extract(dependency.detail,'$.imported_name')=import.imported_name))
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context ON context.summary_id=unit.summary_id
WHERE ?3='macro' AND cr_cfg(import.cfg_condition,json(context.cfg_atoms))<>0;
