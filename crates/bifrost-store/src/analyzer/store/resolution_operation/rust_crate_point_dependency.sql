-- The owner is found by its topology through the crosswalk index, then checked
-- against the selected view, so the view's validity rule stays the only rule.
WITH owner_versions AS (
 SELECT versions.workspace_id, versions.lang, versions.generation,
        versions.unit_key, versions.valid_from
 FROM main.rust_resolution_unit_summary_versions AS versions
  INDEXED BY rust_resolution_unit_summary_versions_topology
 WHERE versions.topology_id=?1
),
owner AS (
 SELECT units.workspace_id, units.lang, units.generation, units.revision, units.summary_id
 FROM owner_versions AS versions
 CROSS JOIN selected_rust_unit_summaries AS units
  ON units.workspace_id=versions.workspace_id AND units.lang=versions.lang
 AND units.generation=versions.generation AND units.unit_key=versions.unit_key
 AND units.valid_from=versions.valid_from
),
-- The unit keys this owner depends on under the extern name ?2: a declared
-- dependency, or a crate-root `extern crate` import of the same name.
dependency_keys(unit_key) AS (
 SELECT dependency.dependency_unit_key
 FROM owner
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=owner.summary_id
 CROSS JOIN main.rust_unit_summary_dependency_names AS name
  ON name.summary_id=dependency.summary_id
 AND name.dependency_ordinal=dependency.dependency_ordinal AND name.extern_name=?2
 UNION
 SELECT dependency.dependency_unit_key
 FROM owner
 CROSS JOIN main.rust_unit_summary_placements AS placement
  ON placement.summary_id=owner.summary_id AND placement.module_path='crate'
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
 CROSS JOIN source_rust_import_targets AS import
  ON import.blob_id=member.blob_id
 CROSS JOIN main.rust_unit_summary_dependency_names AS name
  ON name.summary_id=owner.summary_id AND name.extern_name=import.imported_name
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=name.summary_id
 AND dependency.dependency_ordinal=name.dependency_ordinal
 WHERE import.is_extern_crate=1 AND import.bound_name=?2
  AND import.local_start IS NULL AND COALESCE(import.owner_module,'')=''
)
