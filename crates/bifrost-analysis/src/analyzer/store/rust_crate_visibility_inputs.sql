INSERT INTO cr_restrictions(module_path, visibility)

 SELECT candidate.module_path, candidate.visibility
 FROM cr_source_declarations AS candidate
 WHERE cr_visibility(candidate.visibility)='restricted'
 UNION
 SELECT member.module_path, imports.visibility
 FROM cr_members AS member
 CROSS JOIN source_rust_import_targets AS imports ON imports.blob_id=member.blob_id
 CROSS JOIN source_imports AS declaration ON declaration.blob_id=imports.blob_id
  AND declaration.import_id=imports.source_import_id
 WHERE cr_visibility(imports.visibility)='restricted'
  AND declaration.declaration_start_byte>=member.start_byte AND declaration.declaration_end_byte<=member.end_byte
  AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module WHERE inner_module.blob_id=member.blob_id
    AND inner_module.scope_ordinal<>member.scope_ordinal
    AND inner_module.start_byte>=member.start_byte AND inner_module.end_byte<=member.end_byte
    AND declaration.declaration_start_byte>=inner_module.start_byte
    AND declaration.declaration_end_byte<=inner_module.end_byte)
;
