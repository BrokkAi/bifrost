-- The value constructor has the intersection of the declaration's domain,
-- every tuple field's domain, and the crate cap on a non-exhaustive struct.
-- NULL constructor_non_exhaustive means the declaration has no value
-- constructor; an empty field relation still admits tuple-zero and unit structs.
WITH constructors AS MATERIALIZED (
  SELECT DISTINCT candidate.module_path, candidate.blob_id, candidate.declaration_id,
         properties.visibility, properties.constructor_non_exhaustive
  FROM cr_source_declarations AS candidate
  CROSS JOIN source_rust_declaration_properties AS properties
    ON properties.blob_id = candidate.blob_id
   AND properties.declaration_id = candidate.declaration_id
  WHERE properties.constructor_non_exhaustive IS NOT NULL
), constraints AS (
  SELECT module_path, blob_id, declaration_id, visibility FROM constructors
  UNION ALL
  SELECT constructor.module_path, constructor.blob_id, constructor.declaration_id,
         field.visibility
  FROM constructors AS constructor
  CROSS JOIN source_rust_constructor_fields AS field
    ON field.blob_id = constructor.blob_id
   AND field.declaration_id = constructor.declaration_id
  UNION ALL
  SELECT module_path, blob_id, declaration_id, 'crate' FROM constructors
  WHERE constructor_non_exhaustive = 1
), domains AS (
  SELECT input.module_path, input.blob_id, input.declaration_id,
         CASE cr_visibility(input.visibility)
           WHEN 'public' THEN NULL
           WHEN 'private' THEN input.module_path
           WHEN 'crate' THEN 'crate'
           ELSE restriction.restricted_module_path END AS domain_path,
         cr_visibility(input.visibility) = 'restricted'
           AND restriction.restricted_module_path IS NULL AS unresolved
  FROM constraints AS input
  LEFT JOIN cr_restrictions AS restriction
    ON restriction.module_path = input.module_path
   AND restriction.visibility = input.visibility
), narrowest AS (
  -- The route resolver admits only ancestors of the declaring module. These
  -- domains form a chain of path prefixes, so lexical MAX is the narrowest
  -- resolved domain. Public contributes no domain; an unresolved restriction
  -- must invalidate the intersection even when another constraint resolved.
  SELECT module_path, blob_id, declaration_id,
         MAX(domain_path) AS domain_path, MAX(unresolved) AS unresolved
  FROM domains GROUP BY module_path, blob_id, declaration_id
)
INSERT INTO cr_constructor_visibilities(module_path, blob_id, declaration_id,
                                       visibility, restricted_module_path)
SELECT module_path, blob_id, declaration_id,
       CASE WHEN unresolved = 1 THEN NULL
            WHEN domain_path IS NULL THEN 'public'
            WHEN domain_path = 'crate' THEN 'crate'
            WHEN domain_path = module_path THEN 'private'
            ELSE 'restricted' END,
       CASE WHEN unresolved = 0 AND domain_path <> 'crate' AND domain_path <> module_path
            THEN domain_path END
FROM narrowest;
