-- Impl headers read the same canonical target set as imports and exports.
-- A conflicting prefix remains ambiguous even if its endpoints later converge.
INSERT OR IGNORE INTO cr_impl_bindings
WITH candidates AS (
 SELECT source.blob_id,source.relation_key,source.module_path,
 target.target_crate_key,target.target_module_path,target.target_name
 FROM cr_impl_sources source
 CROSS JOIN cr_binding_route_sources request
 ON request.segments_table='cr_impl_{side}_segments' AND request.blob_id=source.blob_id
 AND request.source_key=source.relation_key AND request.module_path=source.module_path
 CROSS JOIN cr_binding_imports input ON input.blob_id=request.blob_id
 AND input.import_ordinal=request.import_ordinal AND input.module_path=request.module_path
 CROSS JOIN cr_binding_lookups lookup ON lookup.blob_id=input.blob_id
 AND lookup.import_ordinal=input.import_ordinal AND lookup.module_path=input.module_path
 AND lookup.position=input.segments AND lookup.namespace='type'
 CROSS JOIN cr_binding_targets target ON target.owner=lookup.owner
 AND target.namespace=lookup.namespace AND target.name=lookup.name
 CROSS JOIN cr_binding_owners owner ON owner.owner=lookup.owner
 WHERE NOT EXISTS(SELECT 1 FROM cr_gaps gap
 WHERE gap.gap_kind='open_export_inventory' AND gap.subject=owner.module_path || '::' || lookup.name
 AND json_extract(gap.detail,'$.namespace')='type'
 AND json_extract(gap.detail,'$.member_blob')=owner.blob_id
 AND json_extract(gap.detail,'$.binder_scope')=owner.binder_scope)
 GROUP BY source.blob_id,source.relation_key,source.module_path,
 target.target_crate_key,target.target_module_path,target.target_name
)
SELECT blob_id,relation_key,module_path,'{side}',target_crate_key,target_module_path,target_name
FROM candidates GROUP BY blob_id,relation_key,module_path HAVING COUNT(*)=1;
