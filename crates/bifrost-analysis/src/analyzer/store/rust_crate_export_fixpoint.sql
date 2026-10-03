-- `pub use` becomes an export row of the re-exporting module. The route's
-- target crate is this crate for an internal re-export and a dependency for a
-- cross-crate one; `cr_exports` holds both under their crate key, the
-- dependency's rows loaded from its published export surface in the wave that
-- derived it, so one statement covers both.
INSERT INTO cr_exports(crate_key, module_path, namespace, name, origin, visibility,
                       restricted_module_path, declaration_blob_id, declaration_site)
SELECT ?1, source.module_path, target.namespace,
       CASE WHEN source.is_glob = 1 THEN target.name ELSE source.bound_name END,
       CASE WHEN source.is_glob = 1 THEN 'glob_reexport' ELSE 'reexport' END,
       cr_visibility(source.visibility),
       (SELECT restricted_module_path FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility),
       target.declaration_blob_id, target.declaration_site
FROM cr_source_imports AS source
JOIN cr_members AS member ON member.module_path = source.module_path AND member.blob_id = source.blob_id
JOIN cr_routes AS route ON route.blob_id = source.blob_id AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
JOIN cr_exports AS target ON target.crate_key = route.target_crate_key
 AND target.module_path = route.target_module_path
 AND (source.is_glob = 1 OR target.name = source.imported_name)
WHERE (cr_visibility(source.visibility)<>'restricted' OR EXISTS(SELECT 1 FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility AND restricted_module_path IS NOT NULL))
 AND source.visibility <> 'private'
 AND (source.is_glob = 1 OR source.bound_name IS NOT NULL)
 AND (source.is_glob = 0 OR target.visibility <> 'private')
 AND (source.is_glob = 0 OR NOT EXISTS(
       SELECT 1 FROM cr_source_imports AS explicit
       WHERE explicit.module_path = source.module_path
         AND explicit.is_glob = 0 AND explicit.bound_name = target.name))
 AND NOT EXISTS(SELECT 1 FROM cr_exports AS present
                WHERE present.crate_key = ?1
                  AND present.module_path = source.module_path AND present.namespace = target.namespace
                  AND present.name = CASE WHEN source.is_glob = 1 THEN target.name ELSE source.bound_name END
                  AND (present.origin <> 'glob_reexport' OR source.is_glob = 1))
ON CONFLICT(crate_key, module_path, namespace, name) DO UPDATE SET
  origin = excluded.origin, visibility = excluded.visibility,
  restricted_module_path = excluded.restricted_module_path,
  declaration_blob_id = excluded.declaration_blob_id,
  declaration_site = excluded.declaration_site
WHERE cr_exports.origin = 'glob_reexport' AND excluded.origin = 'reexport';
