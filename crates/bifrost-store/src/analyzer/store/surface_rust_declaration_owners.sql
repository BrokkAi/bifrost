WITH items AS (
  SELECT blob_id, declaration_id FROM main.source_rust_declaration_properties WHERE blob_id=?1
  UNION
  SELECT blob_id, declaration FROM main.resolution_rust_declaration_authorities WHERE blob_id=?1
  UNION
  SELECT blob_id, declaration_id FROM main.source_rust_impl_items WHERE blob_id=?1
), native_owners AS (
  SELECT authority.blob_id, authority.declaration, lexical.scope
  FROM main.resolution_rust_declaration_authorities AS authority
  JOIN temp.surface_rust_lexical_declarations_source AS lexical
    ON lexical.blob_id=authority.blob_id AND lexical.semantic_key=authority.semantic_key
  WHERE authority.blob_id=?1
)
SELECT DISTINCT item.blob_id, item.declaration_id,
       COALESCE(module.ordinal, 0) AS module_scope,
       CASE WHEN impl_item.declaration_id IS NOT NULL THEN impl.enclosing_scope
            ELSE native.scope END AS owner_scope
FROM items AS item
JOIN main.source_declarations AS declaration USING(blob_id, declaration_id)
LEFT JOIN main.rust_module_scopes AS module
  ON module.blob_id=item.blob_id AND declaration.start_byte>=module.body_start
 AND declaration.end_byte<=module.body_end
 AND NOT EXISTS(SELECT 1 FROM main.rust_module_scopes AS inner_module
                WHERE inner_module.blob_id=item.blob_id
                  AND declaration.start_byte>=inner_module.body_start
                  AND declaration.end_byte<=inner_module.body_end
                  AND inner_module.body_start>module.body_start)
LEFT JOIN main.source_rust_impl_items AS impl_item
  ON impl_item.blob_id=item.blob_id AND impl_item.declaration_id=item.declaration_id
LEFT JOIN main.resolution_rust_impl_declarations AS impl
  ON impl.blob_id=item.blob_id AND impl.declaration=item.declaration_id
LEFT JOIN native_owners AS native
  ON native.blob_id=item.blob_id AND native.declaration=item.declaration_id
-- NULL impl.enclosing_scope is unknown, including replayed impls. Never infer
-- its owner from the impl subject reference or replace it with a root identity.
