-- The current unified cache schema. Future changes append a new migration; this
-- baseline must remain schema-compatible with cache_state version 1/1/10.
CREATE TABLE cache_state(
  id                       INTEGER PRIMARY KEY CHECK(id = 1),
  schema_version           INTEGER NOT NULL,
  semantic_schema_version  INTEGER NOT NULL,
  analyzer_schema_version  INTEGER NOT NULL,
  last_gc_at               INTEGER NOT NULL DEFAULT 0,
  blobs_at_last_gc         INTEGER NOT NULL DEFAULT 0,
  gc_claim_until           INTEGER NOT NULL DEFAULT 0,
  embed_fingerprint        TEXT,
  chunker_version          TEXT,
  bm25_tokenizer_version   TEXT
) STRICT;

CREATE TABLE semantic_blobs(
  blob_oid        TEXT PRIMARY KEY CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  language        TEXT,
  materialized_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE TABLE semantic_blob_summaries(
  blob_summary_id INTEGER PRIMARY KEY,
  hash            BLOB NOT NULL UNIQUE CHECK(length(hash) = 32)
) STRICT;

CREATE TABLE semantic_blob_chunks(
  blob_oid          TEXT NOT NULL REFERENCES semantic_blobs(blob_oid) ON DELETE CASCADE,
  chunk_ord         INTEGER NOT NULL,
  kind              TEXT NOT NULL,
  symbol            TEXT,
  start_line        INTEGER,
  end_line          INTEGER,
  fts_tokens        TEXT NOT NULL,
  hash              BLOB NOT NULL CHECK(length(hash) = 32),
  parent_summary_id INTEGER REFERENCES semantic_blob_summaries(blob_summary_id),
  composed_hash     BLOB NOT NULL CHECK(length(composed_hash) = 32),
  PRIMARY KEY(blob_oid, chunk_ord)
) WITHOUT ROWID, STRICT;
CREATE INDEX semantic_blob_chunks_by_hash
  ON semantic_blob_chunks(hash);
CREATE INDEX semantic_blob_chunks_by_parent
  ON semantic_blob_chunks(parent_summary_id);
CREATE INDEX semantic_blob_chunks_by_composed
  ON semantic_blob_chunks(composed_hash);

CREATE TABLE semantic_component_vectors(
  hash   BLOB PRIMARY KEY CHECK(length(hash) = 32),
  dim    INTEGER NOT NULL,
  vector BLOB NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TABLE semantic_vectors(
  composed_hash BLOB PRIMARY KEY CHECK(length(composed_hash) = 32),
  dim           INTEGER NOT NULL,
  vector        BLOB NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TABLE analysis_epochs(
  lang  TEXT PRIMARY KEY,
  epoch TEXT NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TABLE blobs(
  blob_oid TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  lang     TEXT NOT NULL,
  PRIMARY KEY(blob_oid, lang)
) WITHOUT ROWID, STRICT;

CREATE TABLE code_units(
  blob_oid                 TEXT    NOT NULL,
  lang                     TEXT    NOT NULL,
  unit_key                 INTEGER NOT NULL,
  kind                     INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
  short_name               TEXT    NOT NULL,
  identifier               TEXT    NOT NULL,
  content_qualifier        TEXT    NOT NULL,
  exact_fqn                TEXT,
  normalized_fqn           TEXT,
  simple_type_name         TEXT,
  signature                TEXT,
  synthetic                INTEGER NOT NULL CHECK(synthetic IN (0, 1)),
  is_type_alias            INTEGER NOT NULL CHECK(is_type_alias IN (0, 1)),
  top_level_ordinal        INTEGER CHECK(top_level_ordinal IS NULL OR top_level_ordinal >= 0),
  in_declarations          INTEGER NOT NULL CHECK(in_declarations IN (0, 1)),
  in_definition_lookup     INTEGER NOT NULL CHECK(in_definition_lookup IN (0, 1)),
  PRIMARY KEY(blob_oid, lang, unit_key),
  CHECK(kind <> 5),
  CHECK(NOT (kind = 3 AND lang IN ('javascript', 'python', 'typescript'))),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_code_units_lang_short_name
  ON code_units(lang, short_name);
CREATE INDEX idx_code_units_lang_identifier_declarations
  ON code_units(lang, identifier)
  WHERE in_declarations = 1;
CREATE INDEX idx_code_units_lang_exact_fqn_declarations
  ON code_units(lang, exact_fqn)
  WHERE in_declarations = 1;
CREATE INDEX idx_code_units_lang_normalized_fqn_declarations
  ON code_units(lang, normalized_fqn)
  WHERE in_declarations = 1;
CREATE INDEX idx_code_units_lang_package_simple_type_declarations
  ON code_units(lang, content_qualifier, simple_type_name)
  WHERE in_declarations = 1 AND kind = 0;
CREATE INDEX idx_code_units_lang_content_qualifier_declarations
  ON code_units(lang, content_qualifier)
  WHERE in_declarations = 1;

CREATE TABLE unit_ranges(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  start_line  INTEGER NOT NULL,
  end_line    INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
  CHECK(start_byte >= 0 AND end_byte >= start_byte AND start_line >= 0 AND end_line >= start_line),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_unit_ranges_lang_blob_ordinal
  ON unit_ranges(lang, blob_oid, ordinal);

CREATE TABLE unit_signatures(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  text        TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE unit_signature_metadata(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  metadata    BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE unit_supertypes(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  raw         TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE unit_children(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  parent_key  INTEGER NOT NULL,
  child_key   INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, parent_key, child_key, ordinal),
  CHECK(parent_key <> child_key),
  FOREIGN KEY(blob_oid, lang, parent_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_oid, lang, child_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE ruby_method_dispatch_modes(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  mode        INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),
  PRIMARY KEY(blob_oid, lang, unit_key),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE scala_traits(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE import_statements(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  statement   TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE import_details(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  info        BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE blob_meta(
  blob_oid                   TEXT    NOT NULL,
  lang                       TEXT    NOT NULL,
  contains_tests             INTEGER NOT NULL CHECK(contains_tests IN (0, 1)),
  content_package            TEXT    NOT NULL,
  stored_unit_count          INTEGER NOT NULL CHECK(stored_unit_count >= 0),
  range_count                INTEGER NOT NULL CHECK(range_count >= 0),
  signature_count            INTEGER NOT NULL CHECK(signature_count >= 0),
  signature_metadata_count   INTEGER NOT NULL CHECK(signature_metadata_count >= 0),
  supertype_count            INTEGER NOT NULL CHECK(supertype_count >= 0),
  child_count                INTEGER NOT NULL CHECK(child_count >= 0),
  import_statement_count     INTEGER NOT NULL CHECK(import_statement_count >= 0),
  import_count               INTEGER NOT NULL CHECK(import_count >= 0),
  type_identifier_count      INTEGER NOT NULL CHECK(type_identifier_count >= 0),
  ruby_dispatch_count        INTEGER NOT NULL CHECK(ruby_dispatch_count >= 0),
  scala_trait_count          INTEGER NOT NULL CHECK(scala_trait_count >= 0),
  is_complete                INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE type_identifiers(
  blob_oid         TEXT NOT NULL,
  lang             TEXT NOT NULL,
  type_identifier  TEXT NOT NULL,
  PRIMARY KEY(blob_oid, lang, type_identifier),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO cache_state(
  id, schema_version, semantic_schema_version, analyzer_schema_version,
  last_gc_at, blobs_at_last_gc, gc_claim_until
) VALUES(1, 1, 1, 10, 0, 0, 0);
