ALTER TABLE source_rust_declaration_properties
  ADD COLUMN builtin_derives BLOB
  CHECK(builtin_derives IS NULL OR
        (json_valid(builtin_derives, 8) AND
         json_type(builtin_derives) = 'array'));

CREATE INDEX source_rust_declaration_properties_builtin_derives
  ON source_rust_declaration_properties(blob_id, declaration_id)
  WHERE builtin_derives IS NOT NULL;
