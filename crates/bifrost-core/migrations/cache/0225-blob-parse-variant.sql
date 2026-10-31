-- Parse products with the same bytes and language may have distinct contexts.
PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;
ALTER TABLE blobs RENAME TO blobs_0224_old;
CREATE TABLE "blobs"(
  id                    INTEGER PRIMARY KEY,
  blob_oid              TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  lang                  TEXT    NOT NULL,
  parse_variant         BLOB NOT NULL DEFAULT x'' CHECK(length(parse_variant) IN (0, 32)),
  generation            INTEGER NOT NULL DEFAULT 0,
  cascade_logical_rows  INTEGER
    CHECK(cascade_logical_rows IS NULL OR cascade_logical_rows >= 1),
  cascade_payload_bytes INTEGER
    CHECK(cascade_payload_bytes IS NULL OR cascade_payload_bytes >= 0),
  UNIQUE(blob_oid, lang, parse_variant),
  UNIQUE(id, lang)
) STRICT;
INSERT INTO blobs(id, blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes)
SELECT id, blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes
FROM blobs_0224_old;
DROP TABLE blobs_0224_old;
CREATE INDEX idx_blobs_lang_generation ON blobs(lang, generation, blob_oid);
PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;

DROP VIEW live_parsed_blobs;
CREATE VIEW live_parsed_blobs AS
SELECT blobs.id AS blob_id,
       blobs.blob_oid,
       blobs.lang,
       blobs.generation,
       blob_meta.content_package,
       blobs.parse_variant
FROM blobs
JOIN blob_meta ON blob_meta.blob_id = blobs.id
JOIN source_declaration_visibility_readiness AS readiness
  ON readiness.blob_id = blob_meta.blob_id AND readiness.available = 1
LEFT JOIN analysis_epochs
  ON analysis_epochs.lang = blobs.lang
WHERE blob_meta.is_complete = 1
  AND blobs.generation = COALESCE(analysis_epochs.generation, 0);

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
 AND item.facts_version = 1
 AND item.macro_facts_version = 1
 AND item.type_forms_version = 1
 AND item.macro_contexts_version = 1
JOIN source_rust_module_scopes AS scope
  ON scope.blob_id = module.blob_id AND scope.ordinal = 0
JOIN source_rust_module_inventory AS inventory
  ON inventory.blob_id = module.blob_id AND inventory.ordinal = 0
WHERE keys.lang = 'rust';
