WITH candidates(module_path, namespace, name, origin, visibility, restricted_module_path,
                declaration_blob_id, declaration_site) AS (
    SELECT source.module_path, target.namespace, source.bound_name, 'reexport',
           cr_visibility(source.visibility), source.restricted_module_path,
           target.declaration_blob_id, target.declaration_site
    FROM cr_export_delta AS target
    CROSS JOIN cr_export_sources AS source INDEXED BY cr_export_sources_target
    WHERE source.target_crate_key = target.crate_key
      AND source.target_module_path = target.module_path
      AND source.is_glob = 0
      AND source.imported_name = target.name
    UNION ALL
    SELECT source.module_path, target.namespace, target.name, 'glob_reexport',
           cr_visibility(source.visibility), source.restricted_module_path,
           target.declaration_blob_id, target.declaration_site
    FROM cr_export_delta AS target
    CROSS JOIN cr_export_sources AS source INDEXED BY cr_export_sources_target
    WHERE target.visibility <> 'private'
      AND source.target_crate_key = target.crate_key
      AND source.target_module_path = target.module_path
      AND source.is_glob = 1
      AND NOT EXISTS (
          SELECT 1 FROM cr_source_imports AS explicit
          WHERE explicit.module_path = source.module_path
            AND explicit.is_glob = 0 AND explicit.bound_name = target.name
      )
)
INSERT INTO cr_exports(crate_key, module_path, namespace, name, origin, visibility,
                       restricted_module_path, declaration_blob_id, declaration_site)
SELECT ?1, candidate.module_path, candidate.namespace, candidate.name, candidate.origin,
       candidate.visibility, candidate.restricted_module_path,
       candidate.declaration_blob_id, candidate.declaration_site
FROM candidates AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM cr_exports AS present
    WHERE present.crate_key = ?1
      AND present.module_path = candidate.module_path
      AND present.namespace = candidate.namespace
      AND present.name = candidate.name
      AND (present.origin <> 'glob_reexport' OR candidate.origin = 'glob_reexport')
)
ON CONFLICT(crate_key, module_path, namespace, name) DO UPDATE SET
  origin = excluded.origin, visibility = excluded.visibility,
  restricted_module_path = excluded.restricted_module_path,
  declaration_blob_id = excluded.declaration_blob_id,
  declaration_site = excluded.declaration_site
WHERE cr_exports.origin = 'glob_reexport' AND excluded.origin = 'reexport';
