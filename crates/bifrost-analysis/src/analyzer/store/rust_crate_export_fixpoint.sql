WITH candidates(module_path, namespace, name, origin, source_visibility,
                source_restricted_module_path, target_crate_key, target_module_path,
                target_visibility, target_restricted_module_path,
                declaration_blob_id, declaration_site) AS (
    SELECT source.module_path, target.namespace, source.bound_name, 'reexport',
           source.visibility, source.restricted_module_path,
           target.crate_key, target.module_path, target.visibility, target.restricted_module_path,
           target.declaration_blob_id, target.declaration_site
    FROM cr_export_delta AS target
    CROSS JOIN cr_export_sources AS source INDEXED BY cr_export_sources_target
    WHERE source.target_crate_key = target.crate_key
      AND source.target_module_path = target.module_path
      AND source.is_glob = 0
      AND source.imported_name = target.name
    UNION ALL
    SELECT source.module_path, target.namespace, target.name, 'glob_reexport',
           source.visibility, source.restricted_module_path,
           target.crate_key, target.module_path, target.visibility, target.restricted_module_path,
           target.declaration_blob_id, target.declaration_site
    FROM cr_export_delta AS target
    CROSS JOIN cr_export_sources AS source INDEXED BY cr_export_sources_target
    WHERE source.target_crate_key = target.crate_key
      AND source.target_module_path = target.module_path
      AND source.is_glob = 1
      AND NOT EXISTS (
          SELECT 1 FROM cr_module_imports AS explicit
          WHERE explicit.module_path = source.module_path
            AND explicit.is_glob = 0 AND explicit.bound_name = target.name
      )
), domains AS (
    -- NULL is the public domain. All other paths are structured module
    -- identities, not source syntax. A restricted path must be resolved.
    SELECT candidate.*,
           CASE cr_visibility(source_visibility)
             WHEN 'public' THEN NULL
             WHEN 'private' THEN module_path
             WHEN 'crate' THEN 'crate'
             ELSE source_restricted_module_path END AS source_domain,
           CASE target_visibility
             WHEN 'public' THEN NULL
             WHEN 'private' THEN target_module_path
             WHEN 'crate' THEN 'crate'
             WHEN 'restricted' THEN target_restricted_module_path END AS target_domain
    FROM candidates AS candidate
), intersections AS (
    SELECT domains.*,
           CASE WHEN source_domain IS NULL THEN target_domain
                WHEN target_domain IS NULL THEN source_domain
                WHEN source_domain = target_domain
                  OR substr(source_domain, 1, length(target_domain) + 2) = target_domain || '::'
                  THEN source_domain
                WHEN substr(target_domain, 1, length(source_domain) + 2) = source_domain || '::'
                  THEN target_domain END AS domain_path
    FROM domains
    WHERE (cr_visibility(source_visibility) <> 'restricted' OR source_domain IS NOT NULL)
      -- A lexical module path alone cannot grant access across crate keys.
      -- Within this crate the importing module must lie in the target domain.
      AND (target_visibility = 'public'
           OR (target_crate_key = ?1 AND target_domain IS NOT NULL
               AND (module_path = target_domain
                    OR substr(module_path, 1, length(target_domain) + 2) = target_domain || '::')))
)
INSERT INTO cr_exports(crate_key, module_path, namespace, name, origin, visibility,
                       restricted_module_path, declaration_blob_id, declaration_site)
SELECT ?1, candidate.module_path, candidate.namespace, candidate.name, candidate.origin,
       CASE WHEN candidate.domain_path IS NULL THEN 'public'
            WHEN candidate.domain_path = 'crate' THEN 'crate'
            WHEN candidate.domain_path = candidate.module_path THEN 'private'
            ELSE 'restricted' END,
       CASE WHEN candidate.domain_path <> 'crate'
                  AND candidate.domain_path <> candidate.module_path
            THEN candidate.domain_path END,
       candidate.declaration_blob_id, candidate.declaration_site
FROM intersections AS candidate
-- Disjoint domains have no intersection, unlike two public domains.
WHERE (candidate.domain_path IS NOT NULL
       OR (candidate.source_domain IS NULL AND candidate.target_domain IS NULL))
  AND NOT EXISTS (
    SELECT 1 FROM cr_exports AS present
    WHERE present.crate_key = ?1
      AND present.module_path = candidate.module_path
      AND present.namespace = candidate.namespace
      AND present.name = candidate.name
      AND present.origin NOT IN ('glob_reexport', 'reexport')
)
ON CONFLICT(crate_key, module_path, namespace, name) DO UPDATE SET
  origin = excluded.origin, visibility = excluded.visibility,
  restricted_module_path = excluded.restricted_module_path,
  declaration_blob_id = excluded.declaration_blob_id,
  declaration_site = excluded.declaration_site
WHERE (cr_exports.origin = 'glob_reexport' AND excluded.origin = 'reexport')
   OR (cr_exports.origin = excluded.origin
           AND cr_exports.origin IN ('glob_reexport', 'reexport')
           AND cr_exports.declaration_blob_id = excluded.declaration_blob_id
           AND cr_exports.declaration_site = excluded.declaration_site
           -- Accessible domains are ancestors of this same importing module.
           -- Their union is the broader domain; equal domains add no delta.
           AND ((excluded.visibility = 'public' AND cr_exports.visibility <> 'public')
                OR (excluded.visibility = 'crate' AND cr_exports.visibility IN ('private', 'restricted'))
                OR (excluded.visibility = 'restricted'
                    AND (cr_exports.visibility = 'private'
                         OR (cr_exports.visibility = 'restricted'
                             AND length(excluded.restricted_module_path)
                                 < length(cr_exports.restricted_module_path))))));
