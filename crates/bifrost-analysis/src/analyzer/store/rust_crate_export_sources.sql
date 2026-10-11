INSERT INTO cr_export_sources(module_path, blob_id, import_ordinal, bound_name, imported_name,
                              is_glob, visibility, restricted_module_path,
                              target_crate_key, target_module_path)
SELECT source.module_path, source.blob_id, source.import_ordinal, source.bound_name,
       source.imported_name, source.is_glob, source.visibility,
       (SELECT restricted_module_path FROM cr_restrictions
        WHERE module_path=source.module_path AND visibility=source.visibility),
       route.target_crate_key, route.target_module_path
FROM cr_source_imports AS source
JOIN cr_members AS member ON member.module_path = source.module_path AND member.blob_id = source.blob_id
JOIN cr_routes AS route ON route.blob_id = source.blob_id
 AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
WHERE (cr_visibility(source.visibility)<>'restricted' OR EXISTS(
       SELECT 1 FROM cr_restrictions
       WHERE module_path=source.module_path AND visibility=source.visibility
         AND restricted_module_path IS NOT NULL))
 AND source.visibility <> 'private'
 AND (source.is_glob = 1 OR source.bound_name IS NOT NULL);
