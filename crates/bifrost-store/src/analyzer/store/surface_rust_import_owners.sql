WITH placed AS (
  SELECT imports.blob_id, imports.ordinal AS import_ordinal,
         imports.native_scope AS owner_scope, imports.local_start IS NULL AS extern_root_eligible,
         COALESCE(module.ordinal, 0) AS module_scope
  FROM main.source_rust_import_targets AS imports
  LEFT JOIN main.source_imports AS declaration
    ON declaration.blob_id=imports.blob_id AND declaration.import_id=imports.source_import_id
  LEFT JOIN main.rust_module_scopes AS module
    ON module.blob_id=imports.blob_id AND declaration.declaration_start_byte>=module.body_start
   AND declaration.declaration_end_byte<=module.body_end
   AND NOT EXISTS(SELECT 1 FROM main.rust_module_scopes AS inner_module
                  WHERE inner_module.blob_id=imports.blob_id
                    AND declaration.declaration_start_byte>=inner_module.body_start
                    AND declaration.declaration_end_byte<=inner_module.body_end
                    AND inner_module.body_start>module.body_start)
  WHERE imports.blob_id=?1
)
SELECT placed.blob_id, placed.import_ordinal, placed.module_scope, placed.owner_scope,
       placed.owner_scope=module.resolution_scope AS module_import,
       placed.extern_root_eligible
FROM placed
LEFT JOIN main.source_rust_module_scopes AS module
  ON module.blob_id=placed.blob_id AND module.ordinal=placed.module_scope
