-- #13316: source-only inputs to the selected macro emission classifier.
-- The nullable format pin distinguishes historical censuses from a complete
-- argument inventory, including an inventory with no attributes.
ALTER TABLE source_rust_impl_census_files ADD COLUMN arguments_version INTEGER
  CHECK(arguments_version IS NULL OR arguments_version = 1);
-- Reader: attributes and keys at exactly (blob_id, boundary_ordinal).
CREATE TABLE source_rust_macro_attributes(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  boundary_ordinal INTEGER NOT NULL CHECK(boundary_ordinal >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  from_cfg_attr INTEGER NOT NULL CHECK(from_cfg_attr IN (0, 1)),
  UNIQUE(blob_id, boundary_ordinal, ordinal),
  FOREIGN KEY(blob_id, boundary_ordinal)
    REFERENCES source_rust_impl_census_boundaries(blob_id, ordinal) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE source_rust_macro_attribute_paths(
  attribute_id INTEGER NOT NULL REFERENCES source_rust_macro_attributes(id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  segment TEXT NOT NULL,
  PRIMARY KEY(attribute_id, ordinal)
) WITHOUT ROWID, STRICT;
CREATE TABLE source_rust_macro_argument_keys(
  attribute_id INTEGER NOT NULL REFERENCES source_rust_macro_attributes(id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  kind INTEGER NOT NULL CHECK(kind IN (0, 1)),
  name TEXT,
  CHECK((kind = 0 AND name IS NOT NULL) OR (kind = 1 AND name IS NULL)),
  PRIMARY KEY(attribute_id, ordinal)
) WITHOUT ROWID, STRICT;
CREATE TRIGGER source_rust_macro_attributes_no_delete_after_seal
BEFORE DELETE ON source_rust_macro_attributes
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = OLD.blob_id AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_attributes_no_insert_after_seal
BEFORE INSERT ON source_rust_macro_attributes
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = NEW.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_attributes_no_update_after_seal
BEFORE UPDATE ON source_rust_macro_attributes
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id IN (OLD.blob_id, NEW.blob_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_attribute_paths_no_delete_after_seal
BEFORE DELETE ON source_rust_macro_attribute_paths
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id) AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id))
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_attribute_paths_no_insert_after_seal
BEFORE INSERT ON source_rust_macro_attribute_paths
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = NEW.attribute_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_attribute_paths_no_update_after_seal
BEFORE UPDATE ON source_rust_macro_attribute_paths
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id IN ((SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id), (SELECT blob_id FROM source_rust_macro_attributes WHERE id = NEW.attribute_id)) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_argument_keys_no_delete_after_seal
BEFORE DELETE ON source_rust_macro_argument_keys
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id) AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id))
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_argument_keys_no_insert_after_seal
BEFORE INSERT ON source_rust_macro_argument_keys
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id = (SELECT blob_id FROM source_rust_macro_attributes WHERE id = NEW.attribute_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;
CREATE TRIGGER source_rust_macro_argument_keys_no_update_after_seal
BEFORE UPDATE ON source_rust_macro_argument_keys
WHEN EXISTS (SELECT 1 FROM source_fact_manifests WHERE blob_id IN ((SELECT blob_id FROM source_rust_macro_attributes WHERE id = OLD.attribute_id), (SELECT blob_id FROM source_rust_macro_attributes WHERE id = NEW.attribute_id)) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

-- Keep the source manifest's exact row and string-byte accounting.
DROP TRIGGER source_rust_item_manifests_validate_accounting;
CREATE TRIGGER source_rust_item_manifests_validate_accounting
BEFORE UPDATE OF publication_state ON source_fact_manifests
WHEN bifrost_seal_validates(NEW.blob_id) AND OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND EXISTS (
   SELECT 1 FROM source_rust_item_manifests AS item
   WHERE item.blob_id = NEW.blob_id
     AND (item.logical_rows <> 1
           + CASE WHEN item.facts_version = 2 THEN 1 + (SELECT COUNT(*) FROM source_rust_impl_census_boundaries WHERE blob_id = NEW.blob_id) ELSE 0 END
           + (SELECT COUNT(*) FROM source_rust_item_syntax WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_contexts WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_impl_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_trait_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_alias_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_callable_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_value_items WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_generic_parameters WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_body_children WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_callable_parameters WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_macro_expansions WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_item_import_contexts WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_types WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_children WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_wrappers WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_segments WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_generic_lists WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_type_generic_arguments WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_definitions WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_arms WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_pattern_nodes WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_ident_roles WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_inputs WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_input_tokens WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_attributes WHERE blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_attribute_paths p JOIN source_rust_macro_attributes a ON a.id=p.attribute_id WHERE a.blob_id = NEW.blob_id)
           + (SELECT COUNT(*) FROM source_rust_macro_argument_keys k JOIN source_rust_macro_attributes a ON a.id=k.attribute_id WHERE a.blob_id = NEW.blob_id)
       OR item.payload_bytes <> COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0) + COALESCE(length(CAST(name AS BLOB)), 0)) FROM source_rust_item_generic_parameters WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0)) FROM source_rust_item_body_children WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(syntax_kind AS BLOB)), 0) + COALESCE(length(CAST(label AS BLOB)), 0)) FROM source_rust_callable_parameters WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(unsupported_syntax_kind AS BLOB)), 0)) FROM source_rust_types WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(name AS BLOB)), 0)) FROM source_rust_type_segments WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(literal_kind AS BLOB)), 0)
                              + COALESCE(length(CAST(literal_text AS BLOB)), 0)
                              + COALESCE(length(CAST(binding_name AS BLOB)), 0)
                              + COALESCE(length(CAST(separator AS BLOB)), 0))
                      FROM source_rust_macro_pattern_nodes WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(name AS BLOB)))
                       FROM source_rust_macro_ident_roles WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(transcriber_identifiers AS BLOB)))
                       FROM source_rust_macro_arms WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(source AS BLOB))) FROM source_rust_macro_inputs WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(syntax_kind AS BLOB))) FROM source_rust_macro_input_tokens WHERE blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(p.segment AS BLOB))) FROM source_rust_macro_attribute_paths p JOIN source_rust_macro_attributes a ON a.id=p.attribute_id WHERE a.blob_id = NEW.blob_id), 0)
           + COALESCE((SELECT SUM(length(CAST(k.name AS BLOB))) FROM source_rust_macro_argument_keys k JOIN source_rust_macro_attributes a ON a.id=k.attribute_id WHERE a.blob_id = NEW.blob_id), 0))
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust item accounting is inconsistent'); END;
