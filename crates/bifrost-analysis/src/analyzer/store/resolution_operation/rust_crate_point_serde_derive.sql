-- Continues `rust_crate_point_targets.sql` with ?3 = 'macro' and ?4 the derive
-- name. Whether the derive name, looked up in module ?2 of topology ?1 as that
-- module sees it (?5, ?6), is bound by `use serde::<name>;`: an import the
-- crate derivation recorded as an `external_dependency` gap (its root is a
-- declared external dependency), whose path is exactly the `serde` segment and
-- whose imported name is the derive's own name. The walk follows glob imports
-- and re-exports, so `use super::*;` reaches a parent module's import. The
-- import's own visibility decides whether the requester sees it, by the rule
-- the export lookup applies to a declaration.
SELECT EXISTS(SELECT 1 FROM targets
 CROSS JOIN rust_crate_gaps AS gap
  ON gap.topology_id=targets.topology_id AND gap.gap_kind='external_dependency'
  AND gap.subject=targets.module_path || '::' || targets.name
 CROSS JOIN json_each(gap.detail, '$.evidence') AS evidence
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=source.blob_id AND import.ordinal=evidence.value ->> 'import_ordinal'
  AND import.bound_name=targets.name AND import.imported_name=?4 AND import.is_glob=0
 CROSS JOIN source_rust_import_module_segments AS root
  ON root.blob_id=import.blob_id AND root.import_ordinal=import.ordinal AND root.ordinal=0
  AND root.segment='serde'
 WHERE NOT EXISTS(SELECT 1 FROM source_rust_import_module_segments AS deeper
                  WHERE deeper.blob_id=import.blob_id AND deeper.import_ordinal=import.ordinal
                    AND deeper.ordinal=1)
  AND (import.visibility='public'
   OR (targets.topology_id=?5 AND (import.visibility='crate'
    OR (import.visibility='private'
        AND (?6=targets.module_path OR substr(?6,1,length(targets.module_path)+2)=targets.module_path || '::'))))))
