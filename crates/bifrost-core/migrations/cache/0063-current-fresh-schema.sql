CREATE TABLE cache_state(
  id                       INTEGER PRIMARY KEY CHECK(id = 1),
  schema_version           INTEGER NOT NULL,
  semantic_schema_version  INTEGER NOT NULL,
  analyzer_schema_version  INTEGER NOT NULL,
  last_gc_at               INTEGER NOT NULL DEFAULT 0,
  blobs_at_last_gc         INTEGER NOT NULL DEFAULT 0,
  gc_claim_until           INTEGER NOT NULL DEFAULT 0,
  embed_fingerprint        TEXT,
  chunker_version          TEXT) STRICT;
CREATE TABLE analysis_epochs(
  lang  TEXT PRIMARY KEY,
  epoch TEXT NOT NULL
, generation INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID, STRICT;
CREATE TABLE analysis_generation_sequence(
  id               INTEGER PRIMARY KEY CHECK(id = 1),
  next_generation  INTEGER NOT NULL CHECK(next_generation > 0)
) STRICT;
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

INSERT INTO cache_state(
  id, schema_version, semantic_schema_version, analyzer_schema_version,
  last_gc_at, blobs_at_last_gc, gc_claim_until
) VALUES(1, 1, 1, 10, 0, 0, 0);

INSERT INTO analysis_generation_sequence(id, next_generation) VALUES(1, 1);
CREATE TABLE semantic_file_chunks(
  blob_oid    TEXT NOT NULL,
  rel_path    TEXT NOT NULL,
  chunk_ord   INTEGER NOT NULL,
  symbol      TEXT NOT NULL,
  start_line  INTEGER,
  end_line    INTEGER,
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
CREATE TABLE reference_fact_epochs(
  lang   TEXT    PRIMARY KEY,
  epoch  INTEGER NOT NULL CHECK(epoch > 0)
) WITHOUT ROWID, STRICT;
CREATE TABLE workspace_revisions(
  workspace_id  TEXT    NOT NULL
    CHECK(length(workspace_id) = 64 AND workspace_id NOT GLOB '*[^0-9a-f]*'),
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL CHECK(generation >= 0),
  revision      INTEGER NOT NULL CHECK(revision > 0),
  PRIMARY KEY(workspace_id, lang, generation, revision)
) WITHOUT ROWID, STRICT;
CREATE TABLE workspace_heads(
  workspace_id  TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  generation    INTEGER NOT NULL,
  revision      INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, lang, generation),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
) WITHOUT ROWID, STRICT;
CREATE TABLE workspace_file_versions(
  file_version_id   INTEGER PRIMARY KEY,
  workspace_id      TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  generation        INTEGER NOT NULL,
  rel_path          TEXT    NOT NULL CHECK(length(rel_path) > 0),
  blob_oid          TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  projection_digest TEXT    NOT NULL
    CHECK(length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
  valid_from         INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until        INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  UNIQUE(workspace_id, lang, generation, rel_path, valid_from),
  UNIQUE(file_version_id, lang),
  FOREIGN KEY(workspace_id, lang, generation, valid_from)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
      ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX idx_workspace_file_versions_open_path
  ON workspace_file_versions(workspace_id, lang, generation, rel_path)
  WHERE valid_until IS NULL;
CREATE INDEX idx_workspace_file_versions_snapshot_path
  ON workspace_file_versions(
    workspace_id, lang, generation, rel_path, valid_from, valid_until, file_version_id
  );
CREATE INDEX idx_workspace_file_versions_snapshot_blob
  ON workspace_file_versions(
    workspace_id, lang, generation, blob_oid, valid_from, valid_until, file_version_id
  );
CREATE TABLE workspace_file_package_rows(
  file_version_id  INTEGER NOT NULL,
  package_name     TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, package_name),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_package_rows_name
  ON workspace_file_package_rows(package_name, file_version_id);
CREATE TABLE workspace_file_package_edge_rows(
  file_version_id      INTEGER NOT NULL,
  parent_package_name  TEXT    NOT NULL,
  child_package_name   TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, parent_package_name, child_package_name),
  CHECK(parent_package_name <> child_package_name),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_package_edge_rows_parent
  ON workspace_file_package_edge_rows(parent_package_name, child_package_name, file_version_id);
CREATE INDEX idx_workspace_file_package_edge_rows_child
  ON workspace_file_package_edge_rows(child_package_name, parent_package_name, file_version_id);
CREATE TABLE workspace_file_anchor_rows(
  file_version_id  INTEGER NOT NULL,
  anchor_kind      TEXT    NOT NULL CHECK(anchor_kind IN ('own_module', 'crate_root')),
  anchor_pop       INTEGER NOT NULL CHECK(anchor_pop BETWEEN 0 AND 255),
  package_name     TEXT    NOT NULL,
  PRIMARY KEY(file_version_id, anchor_kind, anchor_pop),
  CHECK(anchor_kind <> 'crate_root' OR anchor_pop = 0),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_anchor_rows_package
  ON workspace_file_anchor_rows(package_name, anchor_kind, anchor_pop, file_version_id);
CREATE TABLE workspace_file_path_symbol_rows(
  file_version_id  INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
  package_name     TEXT    NOT NULL,
  short_name       TEXT    NOT NULL,
  exact_fqn        TEXT    NOT NULL,
  normalized_fqn   TEXT    NOT NULL, requires_imports INTEGER NOT NULL DEFAULT 0
    CHECK(requires_imports IN (0, 1)),
  PRIMARY KEY(file_version_id, kind, exact_fqn),
  FOREIGN KEY(file_version_id) REFERENCES workspace_file_versions(file_version_id)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_path_symbol_rows_exact
  ON workspace_file_path_symbol_rows(exact_fqn, file_version_id);
CREATE INDEX idx_workspace_file_path_symbol_rows_normalized
  ON workspace_file_path_symbol_rows(normalized_fqn, file_version_id);
CREATE TABLE IF NOT EXISTS "blobs"(
  id                    INTEGER PRIMARY KEY,
  blob_oid              TEXT    NOT NULL
    CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  lang                  TEXT    NOT NULL,
  generation            INTEGER NOT NULL DEFAULT 0,
  cascade_logical_rows  INTEGER
    CHECK(cascade_logical_rows IS NULL OR cascade_logical_rows >= 1),
  cascade_payload_bytes INTEGER
    CHECK(cascade_payload_bytes IS NULL OR cascade_payload_bytes >= 0),
  UNIQUE(blob_oid, lang),
  UNIQUE(id, lang)
) STRICT;
CREATE TABLE IF NOT EXISTS "code_units"(
  blob_id                  INTEGER NOT NULL,
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
  in_test_region           INTEGER NOT NULL DEFAULT 0 CHECK(in_test_region IN (0, 1)),
  fq_anchor_kind           TEXT
    CHECK(fq_anchor_kind IS NULL OR fq_anchor_kind IN ('own_module', 'crate_root')),
  fq_anchor_pop            INTEGER
    CHECK(CASE fq_anchor_kind
      WHEN 'own_module' THEN fq_anchor_pop IS NOT NULL AND fq_anchor_pop BETWEEN 0 AND 255
      WHEN 'crate_root' THEN fq_anchor_pop = 0
      ELSE fq_anchor_kind IS NULL AND fq_anchor_pop IS NULL
    END),
  fq_package_tail_segments INTEGER
    CHECK(fq_package_tail_segments IS NULL OR fq_package_tail_segments >= 0),
  exact_fqn_tail           TEXT,
  normalized_fqn_tail      TEXT
    CHECK(normalized_fqn_tail IS NULL
          OR (exact_fqn_tail IS NOT NULL AND normalized_fqn_tail <> exact_fqn_tail)),
  exact_parent_fqn_tail    TEXT,
  normalized_parent_fqn_tail TEXT
    CHECK(normalized_parent_fqn_tail IS NULL
          OR (exact_parent_fqn_tail IS NOT NULL
              AND normalized_parent_fqn_tail <> exact_parent_fqn_tail)),
  package_fqn_tail         TEXT,
  fq_segment_count         INTEGER NOT NULL DEFAULT 0 CHECK(fq_segment_count >= 0),
  fq_segment_bytes         INTEGER NOT NULL DEFAULT 0 CHECK(fq_segment_bytes >= 0),
  PRIMARY KEY(blob_id, unit_key),
  CHECK(kind <> 5),
  CHECK(NOT (kind = 3 AND lang IN ('javascript', 'python', 'typescript'))),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "code_unit_fq_segments"(
  blob_id      INTEGER NOT NULL,
  lang         TEXT    NOT NULL,
  unit_key     INTEGER NOT NULL,
  seg_ordinal  INTEGER NOT NULL CHECK(seg_ordinal >= 0),
  seg_kind     TEXT    NOT NULL CHECK(seg_kind IN (
    'path', 'package', 'type', 'companion', 'nested', 'member', 'unknown'
  )),
  segment      TEXT    NOT NULL CHECK(length(segment) > 0),
  PRIMARY KEY(blob_id, unit_key, seg_ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_visibility_containers"(
  blob_id                   INTEGER NOT NULL,
  lang                      TEXT    NOT NULL,
  unit_key                  INTEGER NOT NULL,
  container_ordinal         INTEGER NOT NULL CHECK(container_ordinal >= 0),
  exact_container_tail      TEXT    NOT NULL,
  normalized_container_tail TEXT
    CHECK(normalized_container_tail IS NULL
          OR normalized_container_tail <> exact_container_tail),
  PRIMARY KEY(blob_id, unit_key, container_ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_ranges"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  start_line  INTEGER NOT NULL,
  end_line    INTEGER NOT NULL,
  PRIMARY KEY(blob_id, unit_key, ordinal),
  CHECK(start_byte >= 0 AND end_byte >= start_byte AND start_line >= 0 AND end_line >= start_line),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_signatures"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  text        TEXT    NOT NULL,
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_signature_metadata"(
  blob_id                             INTEGER NOT NULL,
  lang                                TEXT    NOT NULL,
  unit_key                            INTEGER NOT NULL,
  ordinal                             INTEGER NOT NULL,
  label                               TEXT    NOT NULL
    CHECK(length(CAST(label AS BLOB)) <= 8388608),
  parameters                          TEXT    NOT NULL DEFAULT '[]'
    CHECK(json_valid(parameters) AND length(CAST(parameters AS BLOB)) <= 8388608),
  return_type_text                    TEXT
    CHECK(return_type_text IS NULL
          OR length(CAST(return_type_text AS BLOB)) <= 8388608),
  return_type_identity                TEXT
    CHECK(return_type_identity IS NULL
          OR (json_valid(return_type_identity)
              AND length(CAST(return_type_identity AS BLOB)) <= 8388608)),
  underlying_type_identity            TEXT
    CHECK(underlying_type_identity IS NULL
          OR (json_valid(underlying_type_identity)
              AND length(CAST(underlying_type_identity AS BLOB)) <= 8388608)),
  declaration_only                    INTEGER NOT NULL DEFAULT 0
    CHECK(declaration_only IN (0, 1)),
  callable_arity_required             INTEGER CHECK(callable_arity_required >= 0),
  callable_arity_total                INTEGER CHECK(callable_arity_total >= 0),
  callable_arity_repeated             INTEGER CHECK(callable_arity_repeated IN (0, 1)),
  type_parameters                     TEXT    NOT NULL DEFAULT '[]'
    CHECK(json_valid(type_parameters)
          AND length(CAST(type_parameters AS BLOB)) <= 8388608),
  bare_return_type_parameter          TEXT
    CHECK(bare_return_type_parameter IS NULL
          OR length(CAST(bare_return_type_parameter AS BLOB)) <= 8388608),
  callable_linkage                    TEXT
    CHECK(callable_linkage IS NULL
          OR callable_linkage IN ('external', 'internal')),
  dispatch_extensibility              TEXT
    CHECK(dispatch_extensibility IS NULL
          OR dispatch_extensibility IN ('open', 'closed')),
  extension_receiver_type             TEXT
    CHECK(extension_receiver_type IS NULL
          OR length(CAST(extension_receiver_type AS BLOB)) <= 8388608),
  extension_receiver_type_identity    TEXT
    CHECK(extension_receiver_type_identity IS NULL
          OR (json_valid(extension_receiver_type_identity)
              AND length(CAST(extension_receiver_type_identity AS BLOB)) <= 8388608)),
  extension_receiver_is_unconstrained INTEGER NOT NULL DEFAULT 0
    CHECK(extension_receiver_is_unconstrained IN (0, 1)),
  field_is_static                     INTEGER NOT NULL DEFAULT 0
    CHECK(field_is_static IN (0, 1)),
  field_is_final                      INTEGER NOT NULL DEFAULT 0
    CHECK(field_is_final IN (0, 1)),
  field_has_initializer               INTEGER NOT NULL DEFAULT 0
    CHECK(field_has_initializer IN (0, 1)),
  cpp_field_linkage                   TEXT
    CHECK(cpp_field_linkage IS NULL
          OR cpp_field_linkage IN ('external', 'internal',
                                   'internal_unless_external_peer')),
  companion_object                    INTEGER NOT NULL DEFAULT 0
    CHECK(companion_object IN (0, 1)),
  callable_is_static                  INTEGER NOT NULL DEFAULT 0
    CHECK(callable_is_static IN (0, 1)),
  callable_is_constructor             INTEGER NOT NULL DEFAULT 0
    CHECK(callable_is_constructor IN (0, 1)),
  callable_declared_visibility        TEXT
    CHECK(callable_declared_visibility IS NULL
          OR callable_declared_visibility IN ('public', 'protected', 'internal',
                                              'package_private', 'private',
                                              'crate_or_module', 'unknown')),
  callable_modifiers_recorded         INTEGER NOT NULL DEFAULT 0
    CHECK(callable_modifiers_recorded IN (0, 1)),
  callable_parameter_types            TEXT
    CHECK(callable_parameter_types IS NULL
          OR (json_valid(callable_parameter_types)
              AND length(CAST(callable_parameter_types AS BLOB)) <= 8388608)),
  callable_is_native                  INTEGER NOT NULL DEFAULT 0
    CHECK(callable_is_native IN (0, 1)),
  class_like_is_interface             INTEGER NOT NULL DEFAULT 0
    CHECK(class_like_is_interface IN (0, 1)),
  class_like_is_static                INTEGER NOT NULL DEFAULT 0
    CHECK(class_like_is_static IN (0, 1)), type_parameters_recorded INTEGER NOT NULL DEFAULT 0
    CHECK(type_parameters_recorded IN (0, 1)), result_type_identities TEXT NOT NULL DEFAULT '[]'
    CHECK(json_valid(result_type_identities)
          AND length(CAST(result_type_identities AS BLOB)) <= 8388608), parameter_type_identities TEXT NOT NULL DEFAULT '[]'
    CHECK(json_valid(parameter_type_identities)
          AND length(CAST(parameter_type_identities AS BLOB)) <= 8388608), callable_override_modifier TEXT DEFAULT NULL
    CHECK(callable_override_modifier IS NULL
          OR callable_override_modifier IN
             ('not_declared', 'virtual', 'abstract', 'override', 'hiding')),
  CHECK((callable_arity_required IS NULL) = (callable_arity_total IS NULL)),
  CHECK((callable_arity_required IS NULL) = (callable_arity_repeated IS NULL)),
  CHECK(callable_arity_required IS NULL
        OR callable_arity_required <= callable_arity_total),
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_supertypes"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  raw         TEXT    NOT NULL,
  lookup_path TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_children"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  parent_key  INTEGER NOT NULL,
  child_key   INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, parent_key, child_key, ordinal),
  CHECK(parent_key <> child_key),
  FOREIGN KEY(blob_id, parent_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, child_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "unit_cpp_template_metadata"(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  metadata BLOB    NOT NULL,
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "ruby_method_dispatch_modes"(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  mode     INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "scala_traits"(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "scala_exports"(
  blob_id    INTEGER NOT NULL,
  lang       TEXT    NOT NULL,
  owner_key  INTEGER NOT NULL,
  ordinal    INTEGER NOT NULL,
  info       BLOB    NOT NULL,
  PRIMARY KEY(blob_id, owner_key, ordinal),
  FOREIGN KEY(blob_id, owner_key)
    REFERENCES "code_units"(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "import_statements"(
  blob_id                INTEGER NOT NULL,
  lang                   TEXT    NOT NULL,
  ordinal                INTEGER NOT NULL CHECK(ordinal >= 0),
  statement              TEXT    NOT NULL,
  is_wildcard            INTEGER NOT NULL CHECK(is_wildcard IN (0, 1)),
  is_global              INTEGER NOT NULL CHECK(is_global IN (0, 1)),
  identifier             TEXT,
  alias                  TEXT,
  path_kind              TEXT CHECK(path_kind IN ('namespace', 'import_from', 'static_member')),
  declaration_start_byte INTEGER CHECK(declaration_start_byte >= 0),
  binder_start           INTEGER CHECK(binder_start >= 0),
  binder_end             INTEGER CHECK(binder_end >= 0),
  CHECK((binder_start IS NULL) = (binder_end IS NULL)),
  CHECK(binder_start IS NULL OR binder_start <= binder_end),
  CHECK(path_kind IS NULL OR declaration_start_byte IS NOT NULL),
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "import_path_segments"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL CHECK(ordinal >= 0),
  seg_ordinal INTEGER NOT NULL CHECK(seg_ordinal >= 0),
  segment     TEXT    NOT NULL,
  PRIMARY KEY(blob_id, ordinal, seg_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES "import_statements"(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "import_lexical_scopes"(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL CHECK(ordinal >= 0),
  scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
  start_byte    INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte      INTEGER NOT NULL CHECK(end_byte >= 0),
  CHECK(start_byte <= end_byte),
  PRIMARY KEY(blob_id, ordinal, scope_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES "import_statements"(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "import_lexical_prefixes"(
  blob_id        INTEGER NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL CHECK(ordinal >= 0),
  prefix_ordinal INTEGER NOT NULL CHECK(prefix_ordinal >= 0),
  prefix         TEXT    NOT NULL,
  PRIMARY KEY(blob_id, ordinal, prefix_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES "import_statements"(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "reference_identifiers"(
  blob_id    INTEGER NOT NULL,
  lang       TEXT    NOT NULL,
  identifier TEXT    NOT NULL,
  PRIMARY KEY(blob_id, identifier),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "materialization_records"(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  ordinal  INTEGER NOT NULL,
  unit_key INTEGER,
  payload  BLOB    NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_meta"(
  blob_id                    INTEGER NOT NULL,
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
  type_identifier_count      INTEGER NOT NULL CHECK(type_identifier_count >= 0),
  is_complete                INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_optional_fact_manifest"(
  blob_id    INTEGER NOT NULL,
  fact_kind  INTEGER NOT NULL CHECK(fact_kind > 0),
  row_count  INTEGER NOT NULL CHECK(row_count > 0),
  PRIMARY KEY(blob_id, fact_kind),
  FOREIGN KEY(blob_id)
    REFERENCES "blob_meta"(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_payload_costs"(
  blob_id        INTEGER NOT NULL,
  payload_bytes  INTEGER NOT NULL CHECK(payload_bytes >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES "blob_meta"(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "blob_reference_fact_manifests"(
  blob_id           INTEGER NOT NULL,
  lang              TEXT    NOT NULL,
  epoch             INTEGER NOT NULL CHECK(epoch > 0),
  identifier_count  INTEGER NOT NULL CHECK(identifier_count >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_exports"(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  exported_name TEXT,
  source_path   TEXT    NOT NULL,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_import_targets"(
  blob_id         INTEGER NOT NULL,
  lang            TEXT    NOT NULL,
  ordinal         INTEGER NOT NULL,
  module_path     TEXT    NOT NULL,
  bound_name      TEXT,
  imported_name   TEXT,
  is_glob         INTEGER NOT NULL,
  visibility      TEXT    NOT NULL,
  owner_module    TEXT    NOT NULL,
  owner_start     INTEGER NOT NULL,
  owner_end       INTEGER NOT NULL,
  local_start     INTEGER,
  local_end       INTEGER,
  cfg_condition   TEXT    NOT NULL DEFAULT 'always',
  is_extern_crate INTEGER NOT NULL DEFAULT 0, is_macro_use INTEGER NOT NULL DEFAULT 0
    CHECK(is_macro_use IN (0, 1)),
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_modules"(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  module_name TEXT    NOT NULL,
  is_inline   INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_identifier_occurrences"(
  blob_id      INTEGER NOT NULL,
  lang         TEXT    NOT NULL,
  identifier   TEXT    NOT NULL,
  context_mask INTEGER NOT NULL,
  PRIMARY KEY(blob_id, identifier),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_module_scopes"(
  blob_id        INTEGER NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL,
  parent_ordinal INTEGER,
  module_name    TEXT    NOT NULL,
  path_attribute TEXT,
  imports_macros INTEGER NOT NULL,
  body_start     INTEGER NOT NULL,
  body_end       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_module_routes"(
  blob_id           INTEGER NOT NULL,
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
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_module_route_gates"(
  blob_id          INTEGER NOT NULL,
  lang             TEXT    NOT NULL,
  route_ordinal    INTEGER NOT NULL,
  gate_ordinal     INTEGER NOT NULL,
  macro_name       TEXT    NOT NULL,
  invocation_start INTEGER NOT NULL,
  PRIMARY KEY(blob_id, route_ordinal, gate_ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_item_macros"(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  macro_name    TEXT    NOT NULL,
  visible_after INTEGER NOT NULL,
  scope_start   INTEGER NOT NULL,
  scope_end     INTEGER NOT NULL,
  passthrough   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_include_edges"(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  relative_path TEXT    NOT NULL,
  file_name     TEXT    NOT NULL,
  include_start INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "rust_include_host_bindings"(
  blob_id          INTEGER NOT NULL,
  lang             TEXT    NOT NULL,
  edge_ordinal     INTEGER NOT NULL,
  ordinal          INTEGER NOT NULL,
  local_name       TEXT    NOT NULL,
  module_specifier TEXT    NOT NULL,
  imported_name    TEXT,
  scope_start      INTEGER NOT NULL,
  kind             TEXT    NOT NULL,
  PRIMARY KEY(blob_id, edge_ordinal, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES "blobs"(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_blobs_lang_generation
  ON blobs(lang, generation, blob_oid);
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
CREATE INDEX idx_code_units_lang_identifier_lookup
  ON code_units(lang, identifier)
  WHERE in_declarations = 1 OR in_definition_lookup = 1;
CREATE INDEX idx_code_units_stable_normalized_tail
  ON code_units(lang, normalized_fqn_tail)
  WHERE fq_anchor_kind IS NULL
    AND normalized_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_anchored_normalized_tail
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, normalized_fqn_tail)
  WHERE fq_anchor_kind IS NOT NULL
    AND normalized_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_stable_parent_identifier
  ON code_units(lang, exact_parent_fqn_tail, identifier)
  WHERE fq_anchor_kind IS NULL
    AND exact_parent_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_anchored_parent_identifier
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, exact_parent_fqn_tail, identifier)
  WHERE fq_anchor_kind IS NOT NULL
    AND exact_parent_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_stable_package_type
  ON code_units(lang, package_fqn_tail, simple_type_name)
  WHERE fq_anchor_kind IS NULL AND in_declarations = 1 AND kind = 0;
CREATE INDEX idx_code_units_anchored_package_type
  ON code_units(lang, fq_anchor_kind, fq_anchor_pop, package_fqn_tail, simple_type_name)
  WHERE fq_anchor_kind IS NOT NULL AND in_declarations = 1 AND kind = 0;
CREATE INDEX idx_code_units_stable_exact_tail
  ON code_units(lang, COALESCE(exact_fqn_tail, ''), blob_id, unit_key)
  WHERE fq_anchor_kind IS NULL
    AND exact_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_code_units_anchored_blob_exact_tail
  ON code_units(
    blob_id, lang, fq_anchor_kind, fq_anchor_pop, exact_fqn_tail, unit_key
  )
  WHERE fq_anchor_kind IS NOT NULL
    AND exact_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
CREATE INDEX idx_unit_ranges_lang_blob_ordinal
  ON unit_ranges(lang, blob_id, ordinal);
CREATE INDEX idx_import_path_segments_by_segment
  ON import_path_segments(lang, segment, blob_id, ordinal, seg_ordinal);
CREATE INDEX idx_reference_identifiers_by_identifier
  ON reference_identifiers(lang, identifier, blob_id);
CREATE INDEX idx_rust_exports_name ON rust_exports(exported_name);
CREATE INDEX idx_rust_import_targets_module ON rust_import_targets(module_path);
CREATE INDEX idx_rust_import_targets_bound ON rust_import_targets(bound_name);
CREATE INDEX idx_rust_identifier_occurrences
  ON rust_identifier_occurrences(lang, identifier);
CREATE INDEX idx_rust_include_edges_file_name
  ON rust_include_edges(lang, file_name);
CREATE VIEW live_parsed_blobs AS
SELECT blobs.id AS blob_id,
       blobs.blob_oid,
       blobs.lang,
       blobs.generation,
       blob_meta.content_package
FROM blobs
JOIN blob_meta
  ON blob_meta.blob_id = blobs.id
LEFT JOIN analysis_epochs
  ON analysis_epochs.lang = blobs.lang
WHERE blob_meta.is_complete = 1
  AND blobs.generation = COALESCE(analysis_epochs.generation, 0);
CREATE VIEW live_code_units AS
SELECT units.*, live.blob_oid
FROM code_units AS units
JOIN live_parsed_blobs AS live
  ON live.blob_id = units.blob_id;
CREATE VIEW live_declarations AS
SELECT *
FROM live_code_units
WHERE in_declarations = 1;
CREATE VIEW live_definition_units AS
SELECT *
FROM live_code_units
WHERE in_declarations = 1 OR in_definition_lookup = 1;
CREATE TABLE structural_fact_manifests(
  blob_id               INTEGER NOT NULL,
  facts_version         INTEGER NOT NULL CHECK(facts_version > 0),
  source_bytes          INTEGER NOT NULL CHECK(source_bytes >= 0),
  node_count            INTEGER NOT NULL CHECK(node_count >= 0),
  role_count            INTEGER NOT NULL CHECK(role_count >= 0),
  occurrence_role_count INTEGER NOT NULL CHECK(occurrence_role_count >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES blob_meta(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE policy_read_keys(
  read_id     INTEGER PRIMARY KEY,
  key_digest  BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind        TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  -- The index family, the lookup kind, or the derived-artifact kind.
  family      TEXT,
  -- The languages this key was folded over, as sorted configuration labels: one
  -- for a file read, the whole scope for a scope read.
  languages   TEXT,
  rel_path    TEXT,
  -- The qualified name a declaration question asks about.
  name        TEXT,
  -- The exact bytes of a name-keyed index probe.
  index_key   BLOB,
  blob_oid    TEXT
    CHECK(blob_oid IS NULL
          OR (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  -- The 32-byte identity this key names: an artifact fingerprint, a call
  -- site's artifact, a summary identity, a content identity, or a policy's
  -- semantic hash.
  subject     BLOB    CHECK(subject IS NULL OR length(subject) = 32),
  start_byte  INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte    INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  -- The digest of the answer a lookup returned, or the non-source input a
  -- models, policy, configuration or epoch key names.
  digest      BLOB    CHECK(digest IS NULL OR length(digest) = 32),
  CHECK((kind = 'file') = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  -- Only a call-site question locates itself inside its file.
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL))
) STRICT;
CREATE UNIQUE INDEX policy_read_keys_identity ON policy_read_keys(key_digest);
CREATE TABLE policy_evaluations(
  evaluation_id             INTEGER PRIMARY KEY,
  base_tree_oid             TEXT    NOT NULL
    CHECK(length(base_tree_oid) = 40 AND base_tree_oid NOT GLOB '*[^0-9a-f]*'),
  policy_set_digest         TEXT    NOT NULL
    CHECK(length(policy_set_digest) = 64 AND policy_set_digest NOT GLOB '*[^0-9a-f]*'),
  options_digest            TEXT    NOT NULL
    CHECK(length(options_digest) = 64 AND options_digest NOT GLOB '*[^0-9a-f]*'),
  configuration_fingerprint TEXT    NOT NULL
    CHECK(length(configuration_fingerprint) = 64
          AND configuration_fingerprint NOT GLOB '*[^0-9a-f]*'),
  active_model_set_hash     TEXT    NOT NULL
    CHECK(length(active_model_set_hash) = 64
          AND active_model_set_hash NOT GLOB '*[^0-9a-f]*'),
  engine_epoch              TEXT    NOT NULL
    CHECK(length(engine_epoch) = 64 AND engine_epoch NOT GLOB '*[^0-9a-f]*'),
  resolved_commit           TEXT    NOT NULL
    CHECK(length(resolved_commit) = 40 AND resolved_commit NOT GLOB '*[^0-9a-f]*'),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0)
) STRICT;
CREATE UNIQUE INDEX policy_evaluations_key ON policy_evaluations(
  base_tree_oid,
  policy_set_digest,
  options_digest,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch
);
CREATE INDEX policy_evaluations_published_at ON policy_evaluations(published_at);
CREATE TABLE policy_evaluation_identities(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  finding_id    BLOB    NOT NULL CHECK(length(finding_id) = 32),
  PRIMARY KEY(evaluation_id, policy_id, finding_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE policy_units(
  unit_id                   INTEGER PRIMARY KEY,
  policy_semantic_hash      TEXT    NOT NULL
    CHECK(length(policy_semantic_hash) = 64
          AND policy_semantic_hash NOT GLOB '*[^0-9a-f]*'),
  family                    TEXT    NOT NULL CHECK(family IN (
    'match', 'assertion', 'taint', 'flow', 'typestate'
  )),
  partition_kind            TEXT    NOT NULL CHECK(partition_kind IN (
    'seed', 'binding', 'assert_file', 'root', 'selector', 'whole'
  )),
  seed_rel_path             TEXT    NOT NULL,
  seed_blob_oid             TEXT    NOT NULL
    CHECK(seed_blob_oid = ''
          OR (length(seed_blob_oid) = 40 AND seed_blob_oid NOT GLOB '*[^0-9a-f]*')),
  -- The digest of what this partition covers within its file, for a partition
  -- whose question is narrower than the file: an assert unit's subject rows,
  -- the name of the row binding a relational unit executed, the semantic
  -- locator of the procedure a typestate root unit solved, or the document
  -- path of the selector a selector unit executed. Empty for the partitions
  -- that cover a whole file or the whole workspace.
  partition_digest          TEXT    NOT NULL
    CHECK(partition_digest = ''
          OR (length(partition_digest) = 64 AND partition_digest NOT GLOB '*[^0-9a-f]*')),
  seed_blob_id              INTEGER,
  lang                      TEXT,
  configuration_fingerprint TEXT    NOT NULL
    CHECK(length(configuration_fingerprint) = 64
          AND configuration_fingerprint NOT GLOB '*[^0-9a-f]*'),
  active_model_set_hash     TEXT    NOT NULL
    CHECK(length(active_model_set_hash) = 64
          AND active_model_set_hash NOT GLOB '*[^0-9a-f]*'),
  engine_epoch              TEXT    NOT NULL
    CHECK(length(engine_epoch) = 64 AND engine_epoch NOT GLOB '*[^0-9a-f]*'),
  -- Only an exhaustive, complete unit may be published: a truncated or
  -- diagnostic-bearing execution is not a partition of a whole one, so a
  -- reader must never find one here to reject at load time.
  completion                TEXT    NOT NULL CHECK(completion = 'complete'),
  budget_mode               TEXT    NOT NULL CHECK(budget_mode = 'exhaustive'),
  product_kind              TEXT    NOT NULL CHECK(product_kind IN (
    'rows', 'assert_file', 'root', 'selector'
  )),
  product                   TEXT    NOT NULL CHECK(json_valid(product)),
  read_set_digest           BLOB    NOT NULL CHECK(length(read_set_digest) = 32),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(seed_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE,
  -- A file-covering unit names the file it covers and the blob that path
  -- resolved to; a whole-policy unit covers the workspace and names neither.
  CHECK((partition_kind = 'whole') = (seed_rel_path = '')),
  CHECK((partition_kind = 'whole') = (seed_blob_oid = '')),
  -- An assert unit's, a binding unit's, a root unit's and a selector unit's
  -- questions are all narrower than the file they cover; a seed unit's is the
  -- file.
  CHECK((partition_kind IN ('assert_file', 'binding', 'root', 'selector'))
        = (partition_digest <> '')),
  CHECK((seed_blob_id IS NULL) = (lang IS NULL)),
  CHECK(partition_kind <> 'whole' OR seed_blob_id IS NULL),
  -- Rendered rows are a query's product, whether the query is a policy's own
  -- selector or one binding of a relational plan; a file's findings are an
  -- assert's, one root's projected violations are a root's, and one seed
  -- file's selected sites are a selector unit's.
  CHECK((partition_kind = 'assert_file') = (product_kind = 'assert_file')),
  CHECK((partition_kind = 'root') = (product_kind = 'root')),
  CHECK((partition_kind = 'selector') = (product_kind = 'selector'))
) STRICT;
CREATE UNIQUE INDEX policy_units_key ON policy_units(
  policy_semantic_hash,
  family,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch,
  partition_kind,
  seed_rel_path,
  seed_blob_oid,
  partition_digest
);
CREATE INDEX policy_units_published_at ON policy_units(published_at);
CREATE INDEX policy_units_seed_blob ON policy_units(seed_blob_id, lang);
CREATE TABLE policy_unit_reads(
  unit_id INTEGER NOT NULL,
  read_id INTEGER NOT NULL,
  PRIMARY KEY(unit_id, read_id),
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE,
  FOREIGN KEY(read_id) REFERENCES policy_read_keys(read_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX policy_unit_reads_by_read ON policy_unit_reads(read_id);
CREATE TABLE policy_evaluation_units(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  unit_id       INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, policy_id, unit_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE,
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX policy_evaluation_units_by_unit ON policy_evaluation_units(unit_id);
CREATE TABLE class_set_summaries(
  summary_id                  INTEGER PRIMARY KEY,
  lookup_digest               BLOB    NOT NULL CHECK(length(lookup_digest) = 32),
  procedure_lineage           BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
  owner_rel_path              TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id               INTEGER NOT NULL,
  lang                        TEXT    NOT NULL,
  artifact_public_identity    BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity   BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version              INTEGER NOT NULL CHECK(schema_version > 0),
  semantics_digest            BLOB    NOT NULL CHECK(length(semantics_digest) = 32),
  context_digest              BLOB    NOT NULL CHECK(length(context_digest) = 32),
  behavior_read_digest        BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  dependency_digest           BLOB    NOT NULL CHECK(length(dependency_digest) = 32),
  carrier_digest              BLOB    NOT NULL CHECK(length(carrier_digest) = 32),
  field_slots_digest          BLOB    NOT NULL CHECK(length(field_slots_digest) = 32),
  entry_fact_ordinal          INTEGER NOT NULL CHECK(entry_fact_ordinal >= 0),
  fact_count                  INTEGER NOT NULL CHECK(fact_count >= 1),
  exit_count                  INTEGER NOT NULL CHECK(exit_count >= 1),
  reached_count               INTEGER NOT NULL CHECK(reached_count >= 0),
  dependency_count            INTEGER NOT NULL CHECK(dependency_count >= 0),
  read_count                  INTEGER NOT NULL CHECK(read_count >= 0),
  charge_count                INTEGER NOT NULL CHECK(charge_count >= 1),
  completion                  TEXT    NOT NULL CHECK(completion = 'complete'),
  budget_mode                 TEXT    NOT NULL CHECK(budget_mode = 'exhaustive'),
  output_digest               BLOB    NOT NULL CHECK(length(output_digest) = 32),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at                INTEGER NOT NULL CHECK(published_at >= 0), root_surface_digest BLOB
    REFERENCES class_set_procedure_surfaces(surface_digest) ON DELETE CASCADE
    CHECK(length(root_surface_digest) = 32), direct_calls_digest BLOB CHECK(length(direct_calls_digest) = 32),
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX class_set_summaries_lookup
  ON class_set_summaries(lookup_digest);
CREATE INDEX class_set_summaries_lineage
  ON class_set_summaries(procedure_lineage);
CREATE INDEX class_set_summaries_owner_blob
  ON class_set_summaries(owner_blob_id, lang);
CREATE TABLE class_set_summary_facts(
  summary_id       INTEGER NOT NULL,
  fact_ordinal     INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  fact_kind        TEXT    NOT NULL CHECK(fact_kind IN ('zero', 'carrier', 'meeting')),
  source_kind      TEXT    NOT NULL CHECK(source_kind IN ('none', 'entry', 'event')),
  source_event_key BLOB,
  carrier_key      BLOB,
  sink_event_key   BLOB,
  uncertain        INTEGER NOT NULL CHECK(uncertain IN (0, 1)),
  PRIMARY KEY(summary_id, fact_ordinal),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK((source_kind = 'event') = (source_event_key IS NOT NULL)),
  CHECK(source_event_key IS NULL OR length(source_event_key) = 32),
  CHECK(carrier_key IS NULL OR length(carrier_key) = 32),
  CHECK(sink_event_key IS NULL OR length(sink_event_key) = 32),
  CHECK((fact_kind = 'zero') =
        (source_kind = 'none' AND carrier_key IS NULL AND sink_event_key IS NULL)),
  CHECK((fact_kind = 'carrier') = (carrier_key IS NOT NULL)),
  CHECK((fact_kind = 'meeting') = (sink_event_key IS NOT NULL)),
  CHECK(fact_kind = 'zero' OR source_kind <> 'none'),
  CHECK(fact_kind <> 'zero' OR uncertain = 0)
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_summary_exits(
  summary_id      INTEGER NOT NULL,
  exit_ordinal    INTEGER NOT NULL CHECK(exit_ordinal >= 0),
  exit_kind       TEXT    NOT NULL CHECK(exit_kind IN ('normal', 'exceptional')),
  fact_ordinal    INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  quality_mask    INTEGER NOT NULL CHECK(quality_mask IN (1, 2, 4, 6, 8)),
  PRIMARY KEY(summary_id, exit_ordinal),
  FOREIGN KEY(summary_id, fact_ordinal)
    REFERENCES class_set_summary_facts(summary_id, fact_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_summary_reached(
  summary_id      INTEGER NOT NULL,
  reached_ordinal INTEGER NOT NULL CHECK(reached_ordinal >= 0),
  point_id        INTEGER NOT NULL CHECK(point_id >= 0),
  fact_ordinal    INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  quality_mask    INTEGER NOT NULL CHECK(quality_mask IN (1, 2, 4, 6, 8)),
  PRIMARY KEY(summary_id, reached_ordinal),
  FOREIGN KEY(summary_id, fact_ordinal)
    REFERENCES class_set_summary_facts(summary_id, fact_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_summary_reads(
  summary_id   INTEGER NOT NULL,
  read_ordinal INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest   BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind         TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  family       TEXT,
  languages    TEXT,
  rel_path     TEXT,
  name         TEXT,
  index_key    BLOB,
  blob_oid     TEXT CHECK(blob_oid IS NULL OR
    (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  subject      BLOB CHECK(subject IS NULL OR length(subject) = 32),
  start_byte   INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte     INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  digest       BLOB CHECK(digest IS NULL OR length(digest) = 32),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK((kind = 'file') = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL)),
  CHECK(CASE kind
    WHEN 'file' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NOT NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'path_absent' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'index' THEN
      family IS NOT NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NOT NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'lookup' THEN
      family IS NOT NULL AND languages IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND digest IS NOT NULL AND (
        (rel_path IS NOT NULL AND name IS NOT NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NOT NULL AND end_byte IS NOT NULL)
        OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NULL AND end_byte IS NULL)
      )
    WHEN 'artifact' THEN
      family IS NOT NULL AND languages IS NULL AND name IS NULL AND index_key IS NULL
      AND blob_oid IS NULL AND subject IS NOT NULL AND start_byte IS NULL
      AND end_byte IS NULL AND digest IS NULL
    WHEN 'scope' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'policy' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NOT NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'models' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'configuration' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'epoch' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    ELSE 0
  END)
) WITHOUT ROWID, STRICT;
CREATE INDEX class_set_summary_reads_by_key
  ON class_set_summary_reads(key_digest, summary_id);
CREATE TABLE class_set_summary_charges(
  summary_id  INTEGER NOT NULL,
  charge_kind TEXT    NOT NULL CHECK(length(charge_kind) > 0),
  amount      INTEGER NOT NULL CHECK(amount > 0),
  PRIMARY KEY(summary_id, charge_kind),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_workspace_file_path_symbol_rows_short
  ON workspace_file_path_symbol_rows(short_name, file_version_id);
CREATE INDEX idx_workspace_file_path_symbol_rows_package
  ON workspace_file_path_symbol_rows(package_name, short_name, file_version_id);
CREATE TABLE class_set_summary_dependencies(
  summary_id                    INTEGER NOT NULL,
  dependency_ordinal            INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  callee_procedure_lineage      BLOB    NOT NULL CHECK(length(callee_procedure_lineage) = 32),
  callee_entry_selector_digest  BLOB    NOT NULL CHECK(length(callee_entry_selector_digest) = 32),
  expected_output_digest        BLOB    NOT NULL CHECK(length(expected_output_digest) = 32),
  consumed_child_lookup_digest  BLOB    NOT NULL CHECK(length(consumed_child_lookup_digest) = 32),
  entry_kind                    TEXT    NOT NULL CHECK(entry_kind IN ('zero', 'carrier')),
  entry_carrier_key             BLOB CHECK(entry_carrier_key IS NULL OR length(entry_carrier_key) = 32),
  entry_uncertain               INTEGER NOT NULL CHECK(entry_uncertain IN (0, 1)),
  entry_source_behavior_digest  BLOB CHECK(entry_source_behavior_digest IS NULL OR length(entry_source_behavior_digest) = 32),
  entry_source_count            INTEGER NOT NULL CHECK(entry_source_count >= 0),
  PRIMARY KEY(summary_id, dependency_ordinal),
  UNIQUE(summary_id, consumed_child_lookup_digest),
  CHECK(
    (entry_kind = 'zero' AND entry_carrier_key IS NULL AND entry_uncertain = 0
      AND entry_source_behavior_digest IS NULL AND entry_source_count = 0)
    OR
    (entry_kind = 'carrier' AND entry_carrier_key IS NOT NULL AND entry_source_count > 0)
  ),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX class_set_summary_dependencies_child_lookup
  ON class_set_summary_dependencies(consumed_child_lookup_digest, summary_id);
CREATE INDEX class_set_summary_dependencies_lineage_entry
  ON class_set_summary_dependencies(
    callee_procedure_lineage, callee_entry_selector_digest, summary_id
  );
CREATE TABLE class_set_summary_dependency_sources(
  summary_id         INTEGER NOT NULL,
  dependency_ordinal INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  source_ordinal     INTEGER NOT NULL CHECK(source_ordinal >= 0),
  source_event_digest BLOB NOT NULL CHECK(length(source_event_digest) = 32),
  PRIMARY KEY(summary_id, dependency_ordinal, source_ordinal),
  UNIQUE(summary_id, dependency_ordinal, source_event_digest),
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES class_set_summary_dependencies(summary_id, dependency_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_procedure_surfaces(
  surface_id                 INTEGER PRIMARY KEY,
  surface_digest             BLOB    NOT NULL CHECK(length(surface_digest) = 32),
  procedure_lineage          BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  artifact_public_identity   BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity  BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version             INTEGER NOT NULL CHECK(schema_version > 0),
  local_structure_digest     BLOB    NOT NULL CHECK(length(local_structure_digest) = 32),
  behavior_read_digest       BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  carrier_semantics_digest   BLOB    NOT NULL CHECK(length(carrier_semantics_digest) = 32),
  direct_calls_digest        BLOB    NOT NULL CHECK(length(direct_calls_digest) = 32),
  call_count                 INTEGER NOT NULL CHECK(call_count >= 0 AND call_count <= 100000),
  binding_count              INTEGER NOT NULL CHECK(binding_count >= 0 AND binding_count <= 1000000),
  entered_count              INTEGER NOT NULL CHECK(entered_count >= 0 AND entered_count <= 1000000),
  lexical_child_count        INTEGER NOT NULL CHECK(lexical_child_count >= 0 AND lexical_child_count <= 100000),
  read_count                 INTEGER NOT NULL CHECK(read_count >= 0 AND read_count <= 100000),
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0), exact_behavior_digest BLOB NOT NULL
    CHECK(length(exact_behavior_digest) = 32), exact_provenance_digest BLOB NOT NULL
    CHECK(length(exact_provenance_digest) = 32),
  UNIQUE(surface_digest),
  CHECK(entered_count <= binding_count),
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;
CREATE INDEX class_set_procedure_surfaces_exact_family
  ON class_set_procedure_surfaces(
    procedure_lineage, owner_rel_path, lang, schema_version,
    local_structure_digest, behavior_read_digest, surface_digest
  );
CREATE INDEX class_set_procedure_surfaces_owner_blob
  ON class_set_procedure_surfaces(owner_blob_id, lang);
CREATE TABLE class_set_procedure_surface_calls(
  surface_id                         INTEGER NOT NULL,
  call_ordinal                       INTEGER NOT NULL CHECK(call_ordinal >= 0),
  has_uncovered_boundary             INTEGER NOT NULL CHECK(has_uncovered_boundary IN (0, 1)),
  truncated                          INTEGER NOT NULL CHECK(truncated = 0),
  complete_receiver_hint_refinable   INTEGER NOT NULL CHECK(complete_receiver_hint_refinable IN (0, 1)),
  dispatch_kind                      TEXT NOT NULL CHECK(dispatch_kind IN ('resolved', 'unavailable')),
  dispatch_status                    TEXT NOT NULL CHECK(dispatch_status IN (
    'complete', 'ambiguous', 'unknown', 'unsupported', 'unproven'
  )),
  dispatch_capability                TEXT,
  dispatch_coverage                  TEXT CHECK(dispatch_coverage IN ('exhaustive', 'open')),
  binding_count                      INTEGER NOT NULL CHECK(binding_count >= 0),
  entered_count                      INTEGER NOT NULL CHECK(entered_count >= 0),
  PRIMARY KEY(surface_id, call_ordinal),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE,
  CHECK((dispatch_status = 'unsupported') = (dispatch_capability IS NOT NULL)),
  CHECK((dispatch_kind = 'resolved') = (dispatch_coverage IS NOT NULL)),
  CHECK(entered_count <= binding_count),
  CHECK(dispatch_kind = 'resolved' OR (binding_count = 0 AND entered_count = 0))
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_procedure_surface_bindings(
  surface_id          INTEGER NOT NULL,
  call_ordinal        INTEGER NOT NULL CHECK(call_ordinal >= 0),
  binding_ordinal     INTEGER NOT NULL CHECK(binding_ordinal >= 0),
  binding_status      TEXT NOT NULL CHECK(binding_status IN (
    'complete', 'ambiguous', 'unknown', 'unsupported', 'unproven'
  )),
  binding_capability  TEXT,
  PRIMARY KEY(surface_id, call_ordinal, binding_ordinal),
  FOREIGN KEY(surface_id, call_ordinal)
    REFERENCES class_set_procedure_surface_calls(surface_id, call_ordinal) ON DELETE CASCADE,
  CHECK((binding_status = 'unsupported') = (binding_capability IS NOT NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_procedure_surface_entered(
  surface_id                       INTEGER NOT NULL,
  call_ordinal                     INTEGER NOT NULL CHECK(call_ordinal >= 0),
  entered_ordinal                  INTEGER NOT NULL CHECK(entered_ordinal >= 0),
  target_procedure_lineage         BLOB NOT NULL CHECK(length(target_procedure_lineage) = 32),
  target_rel_path                  TEXT NOT NULL CHECK(length(target_rel_path) > 0),
  target_lang                      TEXT NOT NULL,
  target_artifact_public_identity  BLOB NOT NULL CHECK(length(target_artifact_public_identity) = 32),
  target_artifact_content_identity BLOB NOT NULL CHECK(length(target_artifact_content_identity) = 32),
  target_local_structure_digest     BLOB NOT NULL CHECK(length(target_local_structure_digest) = 32),
  PRIMARY KEY(surface_id, call_ordinal, entered_ordinal),
  FOREIGN KEY(surface_id, call_ordinal)
    REFERENCES class_set_procedure_surface_calls(surface_id, call_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_procedure_surface_lexical_children(
  surface_id                       INTEGER NOT NULL,
  child_ordinal                    INTEGER NOT NULL CHECK(child_ordinal >= 0),
  child_procedure_lineage          BLOB NOT NULL CHECK(length(child_procedure_lineage) = 32),
  child_rel_path                   TEXT NOT NULL CHECK(length(child_rel_path) > 0),
  child_lang                       TEXT NOT NULL,
  child_artifact_public_identity   BLOB NOT NULL CHECK(length(child_artifact_public_identity) = 32),
  child_artifact_content_identity  BLOB NOT NULL CHECK(length(child_artifact_content_identity) = 32),
  child_local_structure_digest     BLOB NOT NULL CHECK(length(child_local_structure_digest) = 32),
  PRIMARY KEY(surface_id, child_ordinal),
  UNIQUE(surface_id, child_procedure_lineage, child_rel_path, child_lang,
         child_local_structure_digest),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_procedure_surface_reads(
  surface_id    INTEGER NOT NULL,
  read_ordinal  INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest    BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind          TEXT    NOT NULL CHECK(kind = 'lookup'),
  family        TEXT    NOT NULL CHECK(family = 'procedure_dispatch'),
  languages     TEXT,
  rel_path      TEXT    NOT NULL,
  name          TEXT,
  index_key     BLOB,
  blob_oid      TEXT,
  subject       BLOB    NOT NULL CHECK(length(subject) = 32),
  start_byte    INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte      INTEGER NOT NULL CHECK(end_byte >= start_byte),
  digest        BLOB    NOT NULL CHECK(length(digest) = 32),
  PRIMARY KEY(surface_id, read_ordinal),
  UNIQUE(surface_id, key_digest),
  FOREIGN KEY(surface_id) REFERENCES class_set_procedure_surfaces(surface_id) ON DELETE CASCADE,
  CHECK(languages IS NULL AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL)
) WITHOUT ROWID, STRICT;
CREATE INDEX class_set_summaries_root_surface
  ON class_set_summaries(root_surface_digest);
CREATE INDEX class_set_summaries_exact_family
  ON class_set_summaries(
    procedure_lineage, owner_rel_path, lang, schema_version, semantics_digest,
    context_digest, behavior_read_digest, carrier_digest, field_slots_digest,
    root_surface_digest, lookup_digest
  );
CREATE TRIGGER class_set_summaries_require_root_surface_insert
BEFORE INSERT ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;
CREATE TRIGGER class_set_summaries_require_root_surface_update
BEFORE UPDATE OF root_surface_digest, direct_calls_digest ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;
CREATE TABLE class_set_field_slot_indexes (
  index_id                    INTEGER PRIMARY KEY,
  lang                        TEXT    NOT NULL,
  workspace_content_digest    BLOB    NOT NULL CHECK(length(workspace_content_digest) = 32),
  provider_behavior_digest    BLOB    NOT NULL CHECK(length(provider_behavior_digest) = 32),
  active_pack_digest          BLOB    NOT NULL CHECK(length(active_pack_digest) = 32),
  adapter_semantics_digest    BLOB    NOT NULL CHECK(length(adapter_semantics_digest) = 32),
  representation_version      INTEGER NOT NULL CHECK(representation_version > 0),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  slot_count                  INTEGER NOT NULL CHECK(slot_count >= 0),
  atom_count                  INTEGER NOT NULL CHECK(atom_count >= 0),
  artifact_count              INTEGER NOT NULL CHECK(artifact_count >= 0),
  payload_text_bytes          INTEGER NOT NULL CHECK(payload_text_bytes >= 0),
  completion                  TEXT    NOT NULL CHECK(completion = 'complete'),
  published_at                INTEGER NOT NULL, store_survey_count INTEGER NOT NULL DEFAULT 0
    CHECK(store_survey_count >= 0), store_survey_unknown_members INTEGER NOT NULL DEFAULT 0
    CHECK(store_survey_unknown_members IN (0, 1)),
  UNIQUE(lang, workspace_content_digest, provider_behavior_digest,
         active_pack_digest, adapter_semantics_digest, representation_version)
) STRICT;
CREATE INDEX class_set_field_slot_indexes_recent
  ON class_set_field_slot_indexes(lang, published_at DESC, index_id DESC);
CREATE TABLE class_set_field_slot_artifacts (
  index_id                    INTEGER NOT NULL REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  artifact_ordinal            INTEGER NOT NULL CHECK(artifact_ordinal >= 0),
  artifact_rel_path           TEXT    NOT NULL,
  artifact_public_digest      BLOB    NOT NULL CHECK(length(artifact_public_digest) = 32),
  source_bytes                INTEGER NOT NULL CHECK(source_bytes >= 0),
  procedures                  INTEGER NOT NULL CHECK(procedures >= 0),
  blocks                      INTEGER NOT NULL CHECK(blocks >= 0),
  program_points              INTEGER NOT NULL CHECK(program_points >= 0),
  values_count                INTEGER NOT NULL CHECK(values_count >= 0),
  allocations                 INTEGER NOT NULL CHECK(allocations >= 0),
  call_sites                  INTEGER NOT NULL CHECK(call_sites >= 0),
  memory_locations            INTEGER NOT NULL CHECK(memory_locations >= 0),
  captures                    INTEGER NOT NULL CHECK(captures >= 0),
  source_mappings             INTEGER NOT NULL CHECK(source_mappings >= 0),
  evidence                    INTEGER NOT NULL CHECK(evidence >= 0),
  gaps                        INTEGER NOT NULL CHECK(gaps >= 0),
  events                      INTEGER NOT NULL CHECK(events >= 0),
  control_edges               INTEGER NOT NULL CHECK(control_edges >= 0),
  nested_entries              INTEGER NOT NULL CHECK(nested_entries >= 0),
  owned_text_bytes            INTEGER NOT NULL CHECK(owned_text_bytes >= 0),
  PRIMARY KEY(index_id, artifact_ordinal)
) STRICT;
CREATE TABLE class_set_field_slots (
  index_id                    INTEGER NOT NULL REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  slot_ordinal                INTEGER NOT NULL CHECK(slot_ordinal >= 0),
  owner_kind                  TEXT    NOT NULL CHECK(owner_kind IN ('workspace', 'external')),
  owner_declaration_id        TEXT,
  owner_fq_name               TEXT    NOT NULL,
  owner_rel_path              TEXT,
  owner_symbol_id             TEXT,
  member                      TEXT    NOT NULL,
  PRIMARY KEY(index_id, slot_ordinal),
  CHECK(
    (owner_kind = 'workspace' AND owner_declaration_id IS NOT NULL
                              AND owner_rel_path IS NOT NULL
                              AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'external' AND owner_declaration_id IS NULL
                             AND owner_rel_path IS NULL
                             AND owner_symbol_id IS NOT NULL)
  )
) STRICT;
CREATE TABLE class_set_field_slot_atoms (
  index_id                    INTEGER NOT NULL,
  slot_ordinal                INTEGER NOT NULL,
  atom_ordinal                INTEGER NOT NULL CHECK(atom_ordinal >= 0),
  atom_kind                   TEXT    NOT NULL CHECK(atom_kind IN ('workspace', 'external', 'unknown')),
  class_declaration_id        TEXT,
  class_fq_name               TEXT,
  class_rel_path              TEXT,
  class_symbol_id             TEXT,
  unknown_reason              TEXT,
  source_rel_path             TEXT    NOT NULL,
  source_start_byte           INTEGER NOT NULL CHECK(source_start_byte >= 0),
  source_start_line           INTEGER NOT NULL CHECK(source_start_line >= 0),
  source_start_byte_column    INTEGER NOT NULL CHECK(source_start_byte_column >= 0),
  source_end_byte             INTEGER NOT NULL CHECK(source_end_byte >= source_start_byte),
  source_end_line             INTEGER NOT NULL CHECK(source_end_line >= source_start_line),
  source_end_byte_column      INTEGER NOT NULL CHECK(source_end_byte_column >= 0),
  source_kind                 TEXT    NOT NULL CHECK(source_kind IN (
                                  'constructor_call', 'literal', 'container_literal',
                                  'declared_parameter', 'root_receiver', 'unknown')),
  PRIMARY KEY(index_id, slot_ordinal, atom_ordinal),
  FOREIGN KEY(index_id, slot_ordinal)
    REFERENCES class_set_field_slots(index_id, slot_ordinal) ON DELETE CASCADE,
  CHECK(
    (atom_kind = 'workspace' AND class_declaration_id IS NOT NULL
                              AND class_fq_name IS NOT NULL
                              AND class_rel_path IS NOT NULL
                              AND class_symbol_id IS NULL
                              AND unknown_reason IS NULL)
    OR
    (atom_kind = 'external' AND class_declaration_id IS NULL
                             AND class_fq_name IS NOT NULL
                             AND class_rel_path IS NULL
                             AND class_symbol_id IS NOT NULL
                             AND unknown_reason IS NULL)
    OR
    (atom_kind = 'unknown' AND class_declaration_id IS NULL
                            AND class_fq_name IS NULL
                            AND class_rel_path IS NULL
                            AND class_symbol_id IS NULL
                            AND unknown_reason IS NOT NULL)
  )
) STRICT;
CREATE TABLE class_set_root_result_generations (
  generation_id              INTEGER PRIMARY KEY,
  lang                       TEXT    NOT NULL,
  workspace_content_digest   BLOB    NOT NULL CHECK(length(workspace_content_digest) = 32),
  provider_behavior_digest   BLOB    NOT NULL CHECK(length(provider_behavior_digest) = 32),
  active_pack_digest         BLOB    NOT NULL CHECK(length(active_pack_digest) = 32),
  field_slots_digest         BLOB    NOT NULL CHECK(length(field_slots_digest) = 32),
  root_result_semantics_digest BLOB  NOT NULL CHECK(length(root_result_semantics_digest) = 32),
  representation_version     INTEGER NOT NULL CHECK(representation_version > 0),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(lang, workspace_content_digest, provider_behavior_digest,
         active_pack_digest, field_slots_digest, root_result_semantics_digest,
         representation_version),
  UNIQUE(generation_id, lang)
) STRICT;
CREATE INDEX class_set_root_result_generations_recent
  ON class_set_root_result_generations(lang, published_at DESC, generation_id DESC);
CREATE TABLE class_set_finding_free_root_results (
  result_id                  INTEGER PRIMARY KEY,
  generation_id              INTEGER NOT NULL,
  root_public_digest         BLOB    NOT NULL CHECK(length(root_public_digest) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  finding_count              INTEGER NOT NULL CHECK(finding_count = 0),
  row_count                  INTEGER NOT NULL CHECK(row_count >= 0),
  payload_text_bytes         INTEGER NOT NULL CHECK(payload_text_bytes >= 0),
  content_digest             BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(generation_id, root_public_digest),
  FOREIGN KEY(generation_id, lang)
    REFERENCES class_set_root_result_generations(generation_id, lang) ON DELETE CASCADE,
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;
CREATE INDEX class_set_finding_free_root_results_owner_blob
  ON class_set_finding_free_root_results(owner_blob_id, lang);
CREATE TABLE IF NOT EXISTS "structural_fact_nodes"(
  blob_id                 INTEGER NOT NULL,
  node_id                 INTEGER NOT NULL CHECK(node_id >= 0),
  kind                    TEXT    NOT NULL,
  boolean_value           INTEGER CHECK(boolean_value IN (0, 1)),
  construct               TEXT,
  start_byte              INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte                INTEGER NOT NULL CHECK(end_byte >= start_byte),
  parent_node_id          INTEGER CHECK(parent_node_id >= 0 AND parent_node_id < node_id),
  name_start_byte         INTEGER CHECK(name_start_byte >= 0),
  name_end_byte           INTEGER CHECK(name_end_byte >= name_start_byte),
  subtree_end             INTEGER NOT NULL CHECK(subtree_end > node_id),
  call_kind               TEXT CHECK(call_kind IN (
    'function', 'method', 'constructor', 'extractor', 'infix', 'operator',
    'method_value'
  )),
  call_coverage           TEXT CHECK(call_coverage IN (
    'exact', 'partial', 'unknown_macro_derived', 'unknown_dynamic'
  )),
  continues_callee_groups INTEGER CHECK(continues_callee_groups IN (0, 1)),
  PRIMARY KEY(blob_id, node_id),
  FOREIGN KEY(blob_id)
    REFERENCES structural_fact_manifests(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, parent_node_id)
    REFERENCES "structural_fact_nodes"(blob_id, node_id),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL)),
  CHECK(boolean_value IS NULL OR kind = 'boolean_literal'),
  CHECK(
    (call_coverage IS NULL AND call_kind IS NULL AND continues_callee_groups IS NULL)
    OR (call_coverage IS NOT NULL AND continues_callee_groups IS NOT NULL)
  )
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "structural_fact_roles"(
  blob_id            INTEGER NOT NULL,
  source_node_id     INTEGER NOT NULL CHECK(source_node_id >= 0),
  ordinal            INTEGER NOT NULL CHECK(ordinal >= 0),
  role               TEXT    NOT NULL,
  spread             INTEGER NOT NULL CHECK(spread IN (0, 1)),
  keyword_start_byte INTEGER CHECK(keyword_start_byte >= 0),
  keyword_end_byte   INTEGER CHECK(keyword_end_byte >= keyword_start_byte),
  target_node_id     INTEGER CHECK(target_node_id >= 0),
  target_start_byte  INTEGER NOT NULL CHECK(target_start_byte >= 0),
  target_end_byte    INTEGER NOT NULL CHECK(target_end_byte >= target_start_byte),
  name_start_byte    INTEGER CHECK(name_start_byte >= 0),
  name_end_byte      INTEGER CHECK(name_end_byte >= name_start_byte),
  PRIMARY KEY(blob_id, source_node_id, ordinal),
  FOREIGN KEY(blob_id, source_node_id)
    REFERENCES "structural_fact_nodes"(blob_id, node_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, target_node_id)
    REFERENCES "structural_fact_nodes"(blob_id, node_id),
  CHECK((keyword_start_byte IS NULL) = (keyword_end_byte IS NULL)),
  CHECK((name_start_byte IS NULL) = (name_end_byte IS NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS "structural_fact_occurrence_roles"(
  blob_id INTEGER NOT NULL,
  node_id INTEGER NOT NULL CHECK(node_id >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  role    TEXT    NOT NULL CHECK(role IN (
    'declaration_name', 'binder', 'label_or_key', 'type_operand',
    'path_segment', 'import_alias', 'import_target', 'receiver_position',
    'member_position', 'pattern_position', 'generated_source',
    'value_reference'
  )),
  PRIMARY KEY(blob_id, node_id, ordinal),
  FOREIGN KEY(blob_id, node_id)
    REFERENCES "structural_fact_nodes"(blob_id, node_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE class_set_field_slot_stores (
  index_id             INTEGER NOT NULL
    REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  store_ordinal        INTEGER NOT NULL CHECK(store_ordinal >= 0),
  owner_kind           TEXT,
  owner_declaration_id TEXT,
  owner_fq_name        TEXT,
  owner_rel_path       TEXT,
  owner_symbol_id      TEXT,
  member               TEXT NOT NULL,
  PRIMARY KEY(index_id, store_ordinal),
  CHECK(owner_kind IS NULL OR owner_kind IN ('workspace', 'external')),
  CHECK(
    (owner_kind IS NULL AND owner_declaration_id IS NULL
                         AND owner_fq_name IS NULL
                         AND owner_rel_path IS NULL
                         AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'workspace' AND owner_declaration_id IS NOT NULL
                              AND owner_fq_name IS NOT NULL
                              AND owner_rel_path IS NOT NULL
                              AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'external' AND owner_declaration_id IS NULL
                             AND owner_fq_name IS NOT NULL
                             AND owner_rel_path IS NULL
                             AND owner_symbol_id IS NOT NULL)
  )
) STRICT;
CREATE TABLE IF NOT EXISTS "class_set_finding_free_root_rows" (
  result_id                  INTEGER NOT NULL,
  row_ordinal                INTEGER NOT NULL CHECK(row_ordinal >= 0),
  rel_path                   TEXT    NOT NULL CHECK(length(rel_path) > 0),
  start_byte                 INTEGER NOT NULL CHECK(start_byte >= 0),
  start_line                 INTEGER NOT NULL CHECK(start_line >= 0),
  start_byte_column          INTEGER NOT NULL CHECK(start_byte_column >= 0),
  end_byte                   INTEGER NOT NULL CHECK(end_byte >= start_byte),
  end_line                   INTEGER NOT NULL CHECK(end_line >= start_line),
  end_byte_column            INTEGER NOT NULL CHECK(end_byte_column >= 0),
  member                     TEXT    NOT NULL CHECK(length(member) > 0),
  atom_kind                  TEXT    NOT NULL CHECK(atom_kind IN ('workspace', 'external', 'unknown')),
  class_name                 TEXT,
  unknown_reason             TEXT,
  class_set_status           TEXT    NOT NULL CHECK(class_set_status IN (
                                  'known', 'partial', 'no_information', 'inconclusive')),
  guard_class                TEXT,
  PRIMARY KEY(result_id, row_ordinal),
  FOREIGN KEY(result_id)
    REFERENCES class_set_finding_free_root_results(result_id) ON DELETE CASCADE,
  CHECK(end_byte > start_byte
        OR (end_line = start_line AND end_byte_column = start_byte_column)),
  CHECK(end_line <> start_line
        OR end_byte - start_byte = end_byte_column - start_byte_column),
  CHECK(
    (atom_kind IN ('workspace', 'external')
      AND class_name IS NOT NULL AND length(class_name) > 0
      AND unknown_reason IS NULL AND guard_class IS NULL)
    OR
    (atom_kind = 'unknown' AND class_name IS NULL AND guard_class IS NULL
      AND unknown_reason IS NOT NULL AND unknown_reason IN (
        'root_parameter', 'self_receiver', 'variadic_parameter',
        'unresolved_call', 'truncated', 'unmodeled_load', 'await', 'capture',
        'ambiguous_callee', 'external_not_modeled', 'unresolved_base',
        'dynamic_attributes', 'pack_incomplete', 'uncertain_flow',
        'field_slot_incomplete', 'solver_budget', 'semantic_budget',
        'incomplete_root', 'open_type_bound', 'scalar_receiver',
        'class_creation', 'class_object'))
    OR
    (atom_kind = 'unknown' AND class_name IS NULL
      AND unknown_reason IS NOT NULL AND unknown_reason = 'unmodeled_guard'
      AND guard_class IS NOT NULL AND length(guard_class) > 0)
  )
) WITHOUT ROWID, STRICT;
