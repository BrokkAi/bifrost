-- The cache schema at version 18, and the starting point for every store this
-- build creates.
--
-- This file is the fold of the former migrations 0001..0018. They are not
-- reachable any more: a store older than version 18 is refused rather than
-- migrated, and the four files beside this one carry a version 18 store the
-- rest of the way. The design rationale each of those eighteen files carried
-- is in git history at 3e90e6fe, under migrations/cache/.
--
-- It represents version 18, not version 1. `BASELINE_MIGRATION_VERSION` in
-- src/cache_db.rs is what ties the two together, and the constant is asserted
-- against this file's position in the migration list at compile time.
--
-- The SQL below is SQLite's own rendering of the schema those eighteen
-- migrations produced, not a rewrite of it. The quoted table names, the
-- columns appended after a table's closing parenthesis, and the exact
-- whitespace are all load-bearing: SQLite stores a table's defining text
-- verbatim, a store carried forward from an older schema therefore holds this
-- text and not a tidier equivalent, and `verify_upgraded_store` requires an
-- upgraded store and a fresh one to be indistinguishable. Prettifying this
-- file would make every carried-forward store fail that check.
--
-- To change the schema, add a new numbered migration beside this file. Do not
-- edit this one.

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
CREATE TABLE analysis_epochs(
  lang  TEXT PRIMARY KEY,
  epoch TEXT NOT NULL
, generation INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID, STRICT;
CREATE TABLE blobs(
  blob_oid TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  lang     TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0, cascade_logical_rows INTEGER
  CHECK(cascade_logical_rows IS NULL OR cascade_logical_rows >= 1), cascade_payload_bytes INTEGER
  CHECK(cascade_payload_bytes IS NULL OR cascade_payload_bytes >= 0),
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
  in_definition_lookup     INTEGER NOT NULL CHECK(in_definition_lookup IN (0, 1)), in_test_region INTEGER NOT NULL DEFAULT 0
    CHECK (in_test_region IN (0, 1)), fq_segments BLOB,
  PRIMARY KEY(blob_oid, lang, unit_key),
  CHECK(kind <> 5),
  CHECK(NOT (kind = 3 AND lang IN ('javascript', 'python', 'typescript'))),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_code_units_lang_short_name
  ON code_units(lang, short_name);
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
  raw         TEXT    NOT NULL, lookup_path TEXT NOT NULL DEFAULT '',
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
CREATE TABLE type_identifiers(
  blob_oid         TEXT NOT NULL,
  lang             TEXT NOT NULL,
  type_identifier  TEXT NOT NULL,
  PRIMARY KEY(blob_oid, lang, type_identifier),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE path_symbol_units(
  lang            TEXT NOT NULL,
  rel_path        TEXT NOT NULL,
  blob_oid        TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  kind            INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
  package_name    TEXT NOT NULL,
  short_name      TEXT NOT NULL,
  exact_fqn       TEXT NOT NULL,
  normalized_fqn  TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(lang, rel_path, kind, exact_fqn)
) WITHOUT ROWID, STRICT;
CREATE TABLE path_symbol_snapshots(
  lang         TEXT PRIMARY KEY,
  fingerprint  TEXT NOT NULL CHECK(length(fingerprint) = 64)
, generation INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID, STRICT;
CREATE TABLE analysis_generation_sequence(
  id               INTEGER PRIMARY KEY CHECK(id = 1),
  next_generation  INTEGER NOT NULL CHECK(next_generation > 0)
) STRICT;
CREATE INDEX idx_blobs_lang_generation
  ON blobs(lang, generation, blob_oid);
CREATE INDEX idx_path_symbol_units_lang_generation_exact_fqn
  ON path_symbol_units(lang, generation, exact_fqn);
CREATE INDEX idx_path_symbol_units_lang_generation_normalized_fqn
  ON path_symbol_units(lang, generation, normalized_fqn);
CREATE TABLE unit_cpp_template_metadata(
  blob_oid TEXT    NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  metadata BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE scala_exports(
  blob_oid   TEXT    NOT NULL,
  lang       TEXT    NOT NULL,
  owner_key  INTEGER NOT NULL,
  ordinal    INTEGER NOT NULL,
  info       BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, owner_key, ordinal),
  FOREIGN KEY(blob_oid, lang, owner_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_code_units_lang_identifier_lookup
  ON code_units(lang, identifier)
  WHERE in_declarations = 1 OR in_definition_lookup = 1;
CREATE TABLE semantic_pack_active_state(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  active_set_digest TEXT NOT NULL
    CHECK(length(active_set_digest) = 64 AND active_set_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE semantic_pack_active_members(
  ordinal INTEGER PRIMARY KEY CHECK(ordinal >= 0),
  manifest_digest TEXT NOT NULL UNIQUE
    CHECK(length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  source_kind TEXT NOT NULL CHECK(source_kind IN (
    'installed',
    'generated',
    'pre_shipped',
    'workspace_produced',
    'embedded',
    'ephemeral_workspace'
  )),
  source_id TEXT NOT NULL CHECK(length(source_id) > 0),
  workspace_produced INTEGER NOT NULL CHECK(workspace_produced IN (0, 1))
) STRICT;
CREATE INDEX semantic_pack_active_members_source
  ON semantic_pack_active_members(source_kind, source_id, manifest_digest);
CREATE TABLE semantic_files(
  blob_oid        TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  rel_path        TEXT NOT NULL CHECK(length(rel_path) > 0),
  language        TEXT,
  materialized_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(blob_oid, rel_path)
) WITHOUT ROWID, STRICT;
CREATE TABLE semantic_file_chunks(
  blob_oid    TEXT NOT NULL,
  rel_path    TEXT NOT NULL,
  chunk_ord   INTEGER NOT NULL,
  symbol      TEXT NOT NULL,
  start_line  INTEGER,
  end_line    INTEGER,
  fts_tokens  TEXT NOT NULL,
  vector_hash BLOB NOT NULL CHECK(length(vector_hash) = 32),
  PRIMARY KEY(blob_oid, rel_path, chunk_ord),
  FOREIGN KEY(blob_oid, rel_path)
    REFERENCES semantic_files(blob_oid, rel_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX semantic_file_chunks_by_vector
  ON semantic_file_chunks(vector_hash);
CREATE TABLE semantic_vectors(
  vector_hash BLOB PRIMARY KEY CHECK(length(vector_hash) = 32),
  dim         INTEGER NOT NULL,
  vector      BLOB NOT NULL
) WITHOUT ROWID, STRICT;
CREATE TABLE materialization_records(
  blob_oid TEXT    NOT NULL,
  lang     TEXT    NOT NULL,
  ordinal  INTEGER NOT NULL,
  unit_key INTEGER,
  payload  BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_meta"(
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
  is_complete                INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE blob_optional_fact_manifest(
  blob_oid   TEXT    NOT NULL,
  lang       TEXT    NOT NULL,
  fact_kind  INTEGER NOT NULL CHECK(fact_kind > 0),
  row_count  INTEGER NOT NULL CHECK(row_count > 0),
  PRIMARY KEY(blob_oid, lang, fact_kind),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES "blob_meta"(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_payload_costs"(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  payload_bytes  INTEGER NOT NULL CHECK(payload_bytes >= 0),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES "blob_meta"(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "structural_facts_snapshots"(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  snapshot_version  INTEGER NOT NULL CHECK(snapshot_version > 0),
  payload           BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, snapshot_version),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES "blob_meta"(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_exports(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  exported_name TEXT,
  source_path   TEXT    NOT NULL,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_exports_name ON rust_exports(exported_name);
CREATE TABLE rust_import_targets(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  module_path   TEXT    NOT NULL,
  bound_name    TEXT,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  visibility    TEXT    NOT NULL,
  owner_module  TEXT    NOT NULL,
  owner_start   INTEGER NOT NULL,
  owner_end     INTEGER NOT NULL,
  local_start   INTEGER,
  local_end     INTEGER,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_import_targets_module ON rust_import_targets(module_path);
CREATE INDEX idx_rust_import_targets_bound ON rust_import_targets(bound_name);
CREATE TABLE rust_modules(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  module_name TEXT    NOT NULL,
  is_inline   INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_identifier_occurrences(
  blob_oid     TEXT    NOT NULL,
  lang         TEXT    NOT NULL,
  identifier   TEXT    NOT NULL,
  context_mask INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, identifier),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_identifier_occurrences
  ON rust_identifier_occurrences(lang, identifier);
CREATE TABLE rust_module_scopes(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL,
  parent_ordinal INTEGER,
  module_name    TEXT    NOT NULL,
  path_attribute TEXT,
  imports_macros INTEGER NOT NULL,
  body_start     INTEGER NOT NULL,
  body_end       INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_module_routes(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  ordinal           INTEGER NOT NULL,
  scope_ordinal     INTEGER NOT NULL,
  module_name       TEXT    NOT NULL,
  path_attribute    TEXT,
  visibility        TEXT    NOT NULL,
  imports_macros    INTEGER NOT NULL,
  test_gated        INTEGER NOT NULL,
  declaration_start INTEGER NOT NULL,
  declaration_end   INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_module_route_gates(
  blob_oid         TEXT    NOT NULL,
  lang             TEXT    NOT NULL,
  route_ordinal    INTEGER NOT NULL,
  gate_ordinal     INTEGER NOT NULL,
  macro_name       TEXT    NOT NULL,
  invocation_start INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, route_ordinal, gate_ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_item_macros(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  macro_name    TEXT    NOT NULL,
  visible_after INTEGER NOT NULL,
  scope_start   INTEGER NOT NULL,
  scope_end     INTEGER NOT NULL,
  passthrough   INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO cache_state(
  id, schema_version, semantic_schema_version, analyzer_schema_version,
  last_gc_at, blobs_at_last_gc, gc_claim_until
) VALUES(1, 1, 1, 10, 0, 0, 0);

INSERT INTO analysis_generation_sequence(id, next_generation) VALUES(1, 1);
