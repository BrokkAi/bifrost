-- Crate-wide macro-use is inherited at request time, not an own binding.
, macro_prelude_owners AS (
 SELECT DISTINCT provider_owner.owner_id
 FROM selected_rust_unit_summaries AS requester
 CROSS JOIN main.rust_unit_summary_placements AS placement
  ON placement.summary_id=requester.summary_id AND placement.module_path='crate'
 CROSS JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
 CROSS JOIN source_rust_module_scopes AS scope
  ON scope.blob_id=member.blob_id AND scope.ordinal=placement.scope_ordinal
 CROSS JOIN source_rust_import_targets AS imported
  ON imported.blob_id=member.blob_id AND imported.native_scope=scope.resolution_scope
 AND imported.is_extern_crate=1 AND imported.is_macro_use=1
 AND imported.local_start IS NULL AND COALESCE(imported.owner_module,'')=''
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=requester.summary_id
 CROSS JOIN main.rust_unit_summary_dependency_names AS extern_name
  ON extern_name.summary_id=requester.summary_id AND extern_name.extern_name=imported.imported_name
 CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=extern_name.summary_id
 AND dependency.dependency_ordinal=extern_name.dependency_ordinal
 CROSS JOIN selected_rust_unit_summaries AS provider
  ON provider.unit_key=dependency.dependency_unit_key
 CROSS JOIN rust_crate_binding_owners AS provider_owner
  ON provider_owner.topology_id=provider.topology_id
 AND provider_owner.kind='module' AND provider_owner.module_path='crate'
 AND provider_owner.rel_path='' AND provider_owner.scope_identity=X''
 WHERE ?3='macro' AND ?1=?5 AND requester.topology_id=?1
 AND cr_cfg(imported.cfg_condition,json(context.cfg_atoms))=1
)
