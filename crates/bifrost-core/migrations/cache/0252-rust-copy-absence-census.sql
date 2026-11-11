-- #9263: keep historical version-1 Rust facts and require a new census for version 2.
PRAGMA legacy_alter_table = ON;
CREATE TABLE source_rust_item_manifests_0249_new(
  blob_id       INTEGER NOT NULL PRIMARY KEY,
  facts_version INTEGER NOT NULL CHECK(facts_version IN (1, 2)),
  logical_rows  INTEGER NOT NULL CHECK(logical_rows >= 1),
  payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0), macro_facts_version INTEGER
    CHECK(macro_facts_version IS NULL OR macro_facts_version = 1), type_forms_version INTEGER
  CHECK(type_forms_version IS NULL OR type_forms_version = 1), macro_contexts_version INTEGER
    CHECK(macro_contexts_version IS NULL OR macro_contexts_version = 1),
  FOREIGN KEY(blob_id)
    REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

INSERT INTO source_rust_item_manifests_0249_new SELECT * FROM source_rust_item_manifests;
DROP TABLE source_rust_item_manifests;
ALTER TABLE source_rust_item_manifests_0249_new RENAME TO source_rust_item_manifests;
CREATE TRIGGER source_rust_item_manifests_no_delete_after_seal
BEFORE DELETE ON source_rust_item_manifests
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = OLD.blob_id AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Rust item facts are immutable'); END;

CREATE TRIGGER source_rust_item_manifests_no_insert_after_seal
BEFORE INSERT ON source_rust_item_manifests
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = NEW.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_rust_item_manifests_no_update_after_seal
BEFORE UPDATE ON source_rust_item_manifests
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TABLE source_rust_impl_census_files(
  blob_id INTEGER NOT NULL PRIMARY KEY,
  census_version INTEGER NOT NULL CHECK(census_version = 1),
  impl_count INTEGER NOT NULL CHECK(impl_count >= 0),
  boundary_count INTEGER NOT NULL CHECK(boundary_count >= 0),
  FOREIGN KEY(blob_id) REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id) REFERENCES source_rust_item_manifests(blob_id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
CREATE TABLE source_rust_impl_census_boundaries(
  blob_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  start_byte INTEGER NOT NULL CHECK(start_byte >= 0),
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id) REFERENCES source_rust_impl_census_files(blob_id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TRIGGER source_rust_impl_census_files_no_delete_after_seal
BEFORE DELETE ON source_rust_impl_census_files
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = OLD.blob_id AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Rust item facts are immutable'); END;

CREATE TRIGGER source_rust_impl_census_files_no_insert_after_seal
BEFORE INSERT ON source_rust_impl_census_files
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = NEW.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_rust_impl_census_files_no_update_after_seal
BEFORE UPDATE ON source_rust_impl_census_files
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_rust_impl_census_boundaries_no_delete_after_seal
BEFORE DELETE ON source_rust_impl_census_boundaries
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = OLD.blob_id AND publication_state = 'complete')
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed Rust item facts are immutable'); END;

CREATE TRIGGER source_rust_impl_census_boundaries_no_insert_after_seal
BEFORE INSERT ON source_rust_impl_census_boundaries
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id = NEW.blob_id AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

CREATE TRIGGER source_rust_impl_census_boundaries_no_update_after_seal
BEFORE UPDATE ON source_rust_impl_census_boundaries
WHEN EXISTS (SELECT 1 FROM source_fact_manifests
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id) AND publication_state = 'complete')
BEGIN SELECT RAISE(ABORT, 'sealed source facts are immutable'); END;

ALTER TABLE policy_read_keys ADD COLUMN copy_owning_unit BLOB CHECK(copy_owning_unit IS NULL OR length(copy_owning_unit) = 32);
ALTER TABLE policy_read_keys ADD COLUMN copy_target_unit BLOB CHECK(copy_target_unit IS NULL OR length(copy_target_unit) = 32);
ALTER TABLE policy_read_keys ADD COLUMN copy_module_path TEXT;
ALTER TABLE policy_read_keys ADD COLUMN copy_target_identity_digest BLOB CHECK(copy_target_identity_digest IS NULL OR length(copy_target_identity_digest) = 32);
ALTER TABLE policy_read_keys ADD COLUMN copy_census_version INTEGER CHECK(copy_census_version IS NULL OR copy_census_version = 1);
ALTER TABLE policy_read_keys ADD COLUMN copy_config_digest BLOB CHECK(copy_config_digest IS NULL OR length(copy_config_digest) = 32);
ALTER TABLE policy_read_keys ADD COLUMN copy_producer_digest BLOB
  CHECK((family IS 'rust_copy_absence') =
    (copy_owning_unit IS NOT NULL AND copy_target_unit IS NOT NULL
     AND copy_module_path IS NOT NULL AND copy_target_identity_digest IS NOT NULL
     AND copy_census_version IS NOT NULL AND copy_config_digest IS NOT NULL
     AND copy_producer_digest IS NOT NULL))
  CHECK(family IS NOT 'rust_copy_absence' OR kind = 'lookup')
  CHECK(copy_producer_digest IS NULL OR length(copy_producer_digest) = 32)
  CHECK((family IS 'rust_copy_absence') OR
    (copy_owning_unit IS NULL AND copy_target_unit IS NULL AND copy_module_path IS NULL
     AND copy_target_identity_digest IS NULL AND copy_census_version IS NULL
     AND copy_config_digest IS NULL AND copy_producer_digest IS NULL));

DROP VIEW rust_published_fact_blobs;
CREATE VIEW rust_published_fact_blobs AS
SELECT keys.id AS blob_id, keys.blob_oid, keys.lang, keys.generation, keys.parse_variant
FROM blobs AS keys
JOIN blob_meta AS meta
  ON meta.blob_id = keys.id
 AND meta.lang = keys.lang
 AND meta.is_complete = 1
JOIN source_declaration_visibility_readiness AS readiness
  ON readiness.blob_id = keys.id AND readiness.available = 1
JOIN source_fact_manifests AS source
  ON source.blob_id = keys.id
 AND source.publication_state = 'complete'
JOIN source_rust_module_manifests AS module
  ON module.blob_id = keys.id
 AND module.facts_version = 1
JOIN source_rust_item_manifests AS item
  ON item.blob_id = keys.id
 AND item.facts_version = 2
JOIN source_rust_impl_census_files AS census ON census.blob_id = item.blob_id
 AND census.census_version = 1
 AND census.impl_count = (SELECT COUNT(*) FROM source_rust_impl_items WHERE blob_id = census.blob_id)
 AND census.boundary_count = (SELECT COUNT(*) FROM source_rust_impl_census_boundaries WHERE blob_id = census.blob_id)
 AND item.macro_facts_version = 1
 AND item.type_forms_version = 1
 AND item.macro_contexts_version = 1
JOIN source_rust_module_scopes AS scope
  ON scope.blob_id = module.blob_id AND scope.ordinal = 0
JOIN source_rust_module_inventory AS inventory
  ON inventory.blob_id = module.blob_id AND inventory.ordinal = 0
WHERE keys.lang = 'rust';

DROP VIEW source_fact_readiness;
CREATE VIEW source_fact_readiness AS
SELECT visibility.blob_id,
       CASE WHEN visibility.available = 1 AND (
         (meta.go_source_version IS NULL AND go_marker.blob_id IS NULL)
         OR (meta.go_source_version = go_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.java_source_version IS NULL AND java_marker.blob_id IS NULL)
         OR (meta.java_source_version = java_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.ruby_source_version IS NULL AND ruby_marker.blob_id IS NULL)
         OR (meta.ruby_source_version = ruby_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.php_source_version IS NULL AND php_marker.blob_id IS NULL)
         OR (meta.php_source_version = php_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.scala_source_version IS NULL AND scala_marker.blob_id IS NULL)
         OR (meta.scala_source_version = scala_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.cpp_source_version IS NULL AND cpp_marker.blob_id IS NULL)
         OR (meta.cpp_source_version = cpp_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.js_ts_source_version IS NULL AND js_ts_marker.blob_id IS NULL)
         OR (meta.js_ts_source_version = js_ts_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         (meta.python_source_version IS NULL AND python_marker.blob_id IS NULL)
         OR (meta.python_source_version = python_marker.facts_version AND source.publication_state = 'complete')
       ) AND (
         meta.lang <> 'rust'
         OR (
           source.publication_state = 'complete'
           AND rust_module.facts_version = 1
           AND rust_item.facts_version = 2
           AND rust_census.census_version = 1
           AND rust_census.impl_count = (SELECT COUNT(*) FROM source_rust_impl_items WHERE blob_id = meta.blob_id)
           AND rust_census.boundary_count = (SELECT COUNT(*) FROM source_rust_impl_census_boundaries WHERE blob_id = meta.blob_id)
           AND rust_item.macro_facts_version = 1
           AND rust_item.type_forms_version = 1
           AND rust_item.macro_contexts_version = 1
         )
       ) THEN 1 ELSE 0 END AS available
FROM source_declaration_visibility_readiness AS visibility
JOIN blob_meta AS meta ON meta.blob_id = visibility.blob_id
LEFT JOIN source_fact_manifests AS source ON source.blob_id = meta.blob_id
LEFT JOIN source_go_manifests AS go_marker ON go_marker.blob_id = meta.blob_id
LEFT JOIN source_java_declaration_manifests AS java_marker ON java_marker.blob_id = meta.blob_id
LEFT JOIN source_ruby_manifests AS ruby_marker ON ruby_marker.blob_id = meta.blob_id
LEFT JOIN source_php_manifests AS php_marker ON php_marker.blob_id = meta.blob_id
LEFT JOIN source_scala_declaration_manifests AS scala_marker ON scala_marker.blob_id = meta.blob_id
LEFT JOIN source_cpp_manifests AS cpp_marker ON cpp_marker.blob_id = meta.blob_id
LEFT JOIN source_js_ts_manifests AS js_ts_marker ON js_ts_marker.blob_id = meta.blob_id
LEFT JOIN source_python_manifests AS python_marker ON python_marker.blob_id = meta.blob_id
LEFT JOIN source_rust_module_manifests AS rust_module ON rust_module.blob_id = meta.blob_id
LEFT JOIN source_rust_item_manifests AS rust_item ON rust_item.blob_id = meta.blob_id
LEFT JOIN source_rust_impl_census_files AS rust_census ON rust_census.blob_id = meta.blob_id;

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
           + COALESCE((SELECT SUM(length(CAST(syntax_kind AS BLOB))) FROM source_rust_macro_input_tokens WHERE blob_id = NEW.blob_id), 0))
 )
BEGIN SELECT RAISE(ABORT, 'canonical Rust item accounting is inconsistent'); END;

PRAGMA legacy_alter_table = OFF;
