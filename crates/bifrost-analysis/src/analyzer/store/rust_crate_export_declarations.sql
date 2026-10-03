INSERT INTO cr_exports(crate_key, module_path, namespace, name, origin, visibility,
                       restricted_module_path, declaration_blob_id, declaration_site)
SELECT (SELECT crate_key FROM cr_identity),
       CASE WHEN candidate.macro_exported = 1 THEN 'crate' ELSE candidate.module_path END,
       CASE WHEN sites.namespace IN ('type', 'namespace') THEN 'type'
            WHEN sites.namespace = 'macro' THEN 'macro' ELSE 'value' END,
       candidate.identifier, 'declaration',
       CASE WHEN candidate.macro_exported = 1 THEN 'public' ELSE cr_visibility(candidate.visibility) END,
       (SELECT restricted_module_path FROM cr_restrictions
        WHERE module_path=candidate.module_path AND visibility=candidate.visibility),
       candidate.blob_id, sites.source_site
FROM cr_source_declarations AS candidate
CROSS JOIN source_native_declaration_bridges AS bridges
  ON bridges.blob_id = candidate.blob_id
 AND bridges.declaration_id = candidate.declaration_id
CROSS JOIN resolution_semantic_sites AS sites ON sites.blob_id = bridges.blob_id
 AND sites.source_site = bridges.source_site AND sites.semantic_role = 'definition'
WHERE (cr_visibility(candidate.visibility)<>'restricted'
       OR EXISTS(SELECT 1 FROM cr_restrictions
                 WHERE module_path=candidate.module_path
                   AND visibility=candidate.visibility
                   AND restricted_module_path IS NOT NULL))
  AND candidate.nearest_declaration_boundary = 0
  AND candidate.declaration_kind NOT IN (8, 9, 14)
  AND candidate.activation = 1
ON CONFLICT(crate_key, module_path, namespace, name) DO NOTHING;
