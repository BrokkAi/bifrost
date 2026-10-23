INSERT INTO cr_imports
SELECT DISTINCT source.module_path,target.namespace,source.bound_name,source.blob_id,
 source.import_ordinal,original.binder_scope,target.target_crate_key,target.target_module_path,target.target_name
FROM cr_binding_imports source
CROSS JOIN cr_source_imports original ON original.blob_id=source.blob_id
 AND original.import_ordinal=source.import_ordinal AND original.module_path=source.module_path
CROSS JOIN cr_binding_exact_targets target
 ON target.owner=source.owner AND target.name=source.bound_name
WHERE source.is_glob=0 AND source.bound_name IS NOT NULL;
