SELECT DISTINCT imports.native_scope
FROM source_rust_module_scopes AS scope
CROSS JOIN source_fact_manifests AS manifest ON manifest.blob_id=scope.blob_id
LEFT JOIN source_rust_module_declarations AS declaration
 ON declaration.blob_id=scope.blob_id AND declaration.declaration_id=scope.declaration_id
CROSS JOIN source_rust_import_targets AS imports ON imports.blob_id=scope.blob_id
CROSS JOIN source_imports AS import_declaration
 ON import_declaration.blob_id=imports.blob_id AND import_declaration.import_id=imports.source_import_id
WHERE scope.blob_id=?1 AND scope.resolution_scope=?2 AND imports.native_scope IS NOT NULL
 AND import_declaration.declaration_start_byte>=COALESCE(declaration.body_start_byte,0)
 AND import_declaration.declaration_end_byte<=COALESCE(declaration.body_end_byte,manifest.source_bytes)
 AND NOT EXISTS (
  SELECT 1 FROM source_rust_module_scopes AS inner_scope
  CROSS JOIN source_rust_module_declarations AS inner_declaration
   ON inner_declaration.blob_id=inner_scope.blob_id AND inner_declaration.declaration_id=inner_scope.declaration_id
  WHERE inner_scope.blob_id=scope.blob_id AND inner_scope.ordinal<>scope.ordinal
   AND inner_declaration.body_start_byte>=COALESCE(declaration.body_start_byte,0)
   AND inner_declaration.body_end_byte<=COALESCE(declaration.body_end_byte,manifest.source_bytes)
   AND import_declaration.declaration_start_byte>=inner_declaration.body_start_byte
   AND import_declaration.declaration_end_byte<=inner_declaration.body_end_byte
 )
