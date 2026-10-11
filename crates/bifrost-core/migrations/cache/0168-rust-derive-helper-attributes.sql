DROP INDEX source_rust_declaration_properties_serde_helper;

ALTER TABLE source_rust_declaration_properties
  DROP COLUMN serde_helper_derive;

ALTER TABLE source_rust_declaration_properties
  ADD COLUMN derive_helper_attributes BLOB
  CHECK(derive_helper_attributes IS NULL OR
        (json_valid(derive_helper_attributes, 8) AND
         json_type(derive_helper_attributes) = 'array'));

CREATE INDEX source_rust_declaration_properties_derive_helpers
  ON source_rust_declaration_properties(blob_id, declaration_id)
  WHERE derive_helper_attributes IS NOT NULL;
