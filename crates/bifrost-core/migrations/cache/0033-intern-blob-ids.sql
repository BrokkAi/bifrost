-- Intern the blob key. `blobs` mints an integer id; every fact table keys on
-- it (ExecPlan `.agents/plans/store-blob-id-interning.md`).
--
-- Until now a fact row was keyed `(blob_oid, lang)`: a forty-character
-- hexadecimal Git blob OID plus a short storage-language key. Every fact table
-- is `WITHOUT ROWID`, so that key IS the table's storage, and every secondary
-- index entry ends with a copy of it because that is how SQLite points an index
-- entry back at its row. `code_units` has fourteen secondary indexes, so the
-- forty-character string was stored fifteen times per unit.
--
-- The measurement that motivated this is in
-- `.agents/plans/immutable-revision-persisted-fact-reuse.md`: a cold Godot
-- build pushes 4.58M logical rows and 417 MB through the single SQLite writer
-- at roughly 85k rows/s, and the writer is saturated for a ~50 second window
-- while fifteen parsing workers block on a full channel.
--
-- `blob_oid` now survives in exactly three places: `blobs`, which is the intern
-- point; `workspace_file_versions`, which persists across republications and
-- therefore cannot hold an id (see below); and the two `semantic_*` tables,
-- which belong to the retrieval subsystem and have neither a `lang` nor a
-- `blobs` foreign key.
--
-- `blobs` becomes an ordinary rowid table. SQLite aliases the rowid to an
-- `INTEGER PRIMARY KEY` only on a rowid table; on a `WITHOUT ROWID` table it is
-- an ordinary column and the writer would have to allocate ids from a sequence
-- of its own. The alias gives `last_insert_rowid()`, which is the one value the
-- writer needs after inserting the registry row, at no cost. Rowid reuse after
-- a delete is harmless because no id is ever observable outside this database:
-- publication deletes and reinserts the `blobs` row so the cascade clears the
-- previous facts in one statement, so ids churn by design and nothing may cache
-- one across a transaction.
--
-- `UNIQUE(blob_oid, lang)` is the intern index, in that column order because
-- the hot external shape is `blob_oid IN (...) AND lang = ?`, which seeks once
-- per requested OID. `UNIQUE(id, lang)` is a foreign-key target: fact tables
-- that are direct children of `blobs` declare
-- `FOREIGN KEY(blob_id, lang) REFERENCES blobs(id, lang)`, which keeps the
-- schema-level guarantee -- present before this migration through the composite
-- key -- that a fact row's `lang` matches its blob's.
--
-- Every fact table keeps its `lang` column. Twelve of the fourteen `code_units`
-- indexes lead with `lang`, and reshaping indexes is not what this migration is
-- for. The width being bought back is the forty-character hex, not a three-to-
-- twelve character language key.
--
-- `workspace_file_versions` deliberately keeps the hex. Its rows are written
-- once and retained for the life of a workspace revision, while a republished
-- blob gets a NEW id, so a persisted `blob_id` there would rot silently. It
-- also has no foreign key to `blobs` and must not gain one: a retained logical
-- revision names its blob independently of whether facts still exist for it.
-- The join cost that would otherwise argue for interning it is avoided by
-- having `live_parsed_blobs` expose `blob_id` alongside `blob_oid`, so the
-- views that seek `workspace_file_versions` by hex take the hex from a join
-- they already make.
--
-- Mechanics. SQLite cannot retype or re-key a column in place, so each table is
-- created as `<name>_new`, filled, and swapped. Three ordering rules make that
-- safe, and all three are already load-bearing in
-- `bridges/0016-optional-fact-manifest-after-19.sql`:
--
--   1. The four persistent views are dropped first and recreated last.
--      `ALTER TABLE ... RENAME TO ...` reparses the whole schema and fails if a
--      view names a table that no longer exists.
--   2. The migration chain runs with `PRAGMA foreign_keys` ON, and under that
--      pragma `DROP TABLE` performs an implicit `DELETE FROM` that fires
--      cascades. Old tables are therefore dropped children-before-parents.
--   3. Each `_new` table's foreign keys name the other `_new` tables.
--      `ALTER TABLE x_new RENAME TO x` rewrites `REFERENCES x_new` in every
--      other table, so after the last rename every clause names its final
--      table.
--
-- Every copy reads `FROM blobs_new AS b CROSS JOIN <table> AS t ON
-- t.blob_oid = b.blob_oid AND t.lang = b.lang`. `CROSS JOIN` fixes the join
-- order, so the outer loop walks `blobs_new` in rowid order and the inner loop
-- range-scans the source table's own primary key. Because ids are minted in
-- `(blob_oid, lang)` order -- the source tables' own clustering order -- the
-- rows arrive in ascending target-key order, so the inserts append instead of
-- scattering and no sorter runs. That matters: `temp_store` is MEMORY, and
-- sorting a multi-hundred-megabyte table would be held in RAM.
--
-- The joins are inner joins on purpose. A fact row whose `blobs` row is gone is
-- already unreachable -- every fact table cascades from `blobs`, directly or
-- transitively -- and would be unrepresentable afterwards, so dropping it is
-- the correct repair. `validate_foreign_keys` runs at the end of the migration
-- transaction and proves none are left dangling.
--
-- Secondary indexes are created after the data is in, so each is one sorted
-- bulk build rather than a per-row insert into a growing b-tree.

DROP VIEW live_definition_units;
DROP VIEW live_declarations;
DROP VIEW live_code_units;
DROP VIEW live_parsed_blobs;

CREATE TABLE blobs_new(
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

INSERT INTO blobs_new(
  blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes
)
SELECT blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes
FROM blobs
ORDER BY blob_oid, lang;

CREATE TABLE code_units_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO code_units_new(
  blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
  exact_fqn, normalized_fqn, simple_type_name, signature, synthetic,
  is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
  in_test_region, fq_anchor_kind, fq_anchor_pop, fq_package_tail_segments,
  exact_fqn_tail, normalized_fqn_tail, exact_parent_fqn_tail,
  normalized_parent_fqn_tail, package_fqn_tail, fq_segment_count,
  fq_segment_bytes
)
SELECT b.id, t.lang, t.unit_key, t.kind, t.short_name, t.identifier,
       t.content_qualifier, t.exact_fqn, t.normalized_fqn, t.simple_type_name,
       t.signature, t.synthetic, t.is_type_alias, t.top_level_ordinal,
       t.in_declarations, t.in_definition_lookup, t.in_test_region,
       t.fq_anchor_kind, t.fq_anchor_pop, t.fq_package_tail_segments,
       t.exact_fqn_tail, t.normalized_fqn_tail, t.exact_parent_fqn_tail,
       t.normalized_parent_fqn_tail, t.package_fqn_tail, t.fq_segment_count,
       t.fq_segment_bytes
FROM blobs_new AS b
CROSS JOIN code_units AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE code_unit_fq_segments_new(
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
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO code_unit_fq_segments_new(
  blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
)
SELECT b.id, t.lang, t.unit_key, t.seg_ordinal, t.seg_kind, t.segment
FROM blobs_new AS b
CROSS JOIN code_unit_fq_segments AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_visibility_containers_new(
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
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_visibility_containers_new(
  blob_id, lang, unit_key, container_ordinal, exact_container_tail,
  normalized_container_tail
)
SELECT b.id, t.lang, t.unit_key, t.container_ordinal, t.exact_container_tail,
       t.normalized_container_tail
FROM blobs_new AS b
CROSS JOIN unit_visibility_containers AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_ranges_new(
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
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_ranges_new(
  blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
)
SELECT b.id, t.lang, t.unit_key, t.ordinal, t.start_byte, t.end_byte,
       t.start_line, t.end_line
FROM blobs_new AS b
CROSS JOIN unit_ranges AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_signatures_new(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  text        TEXT    NOT NULL,
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_signatures_new(blob_id, lang, unit_key, ordinal, text)
SELECT b.id, t.lang, t.unit_key, t.ordinal, t.text
FROM blobs_new AS b
CROSS JOIN unit_signatures AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_signature_metadata_new(
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
    CHECK(class_like_is_static IN (0, 1)),
  CHECK((callable_arity_required IS NULL) = (callable_arity_total IS NULL)),
  CHECK((callable_arity_required IS NULL) = (callable_arity_repeated IS NULL)),
  CHECK(callable_arity_required IS NULL
        OR callable_arity_required <= callable_arity_total),
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_signature_metadata_new(
  blob_id, lang, unit_key, ordinal, label, parameters, return_type_text,
  return_type_identity, underlying_type_identity, declaration_only,
  callable_arity_required, callable_arity_total, callable_arity_repeated,
  type_parameters, bare_return_type_parameter, callable_linkage,
  dispatch_extensibility, extension_receiver_type,
  extension_receiver_type_identity, extension_receiver_is_unconstrained,
  field_is_static, field_is_final, field_has_initializer, cpp_field_linkage,
  companion_object, callable_is_static, callable_is_constructor,
  callable_declared_visibility, callable_modifiers_recorded,
  callable_parameter_types, callable_is_native, class_like_is_interface,
  class_like_is_static
)
SELECT b.id, t.lang, t.unit_key, t.ordinal, t.label, t.parameters,
       t.return_type_text, t.return_type_identity, t.underlying_type_identity,
       t.declaration_only, t.callable_arity_required, t.callable_arity_total,
       t.callable_arity_repeated, t.type_parameters,
       t.bare_return_type_parameter, t.callable_linkage,
       t.dispatch_extensibility, t.extension_receiver_type,
       t.extension_receiver_type_identity,
       t.extension_receiver_is_unconstrained, t.field_is_static,
       t.field_is_final, t.field_has_initializer, t.cpp_field_linkage,
       t.companion_object, t.callable_is_static, t.callable_is_constructor,
       t.callable_declared_visibility, t.callable_modifiers_recorded,
       t.callable_parameter_types, t.callable_is_native,
       t.class_like_is_interface, t.class_like_is_static
FROM blobs_new AS b
CROSS JOIN unit_signature_metadata AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_supertypes_new(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  unit_key    INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  raw         TEXT    NOT NULL,
  lookup_path TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY(blob_id, unit_key, ordinal),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_supertypes_new(
  blob_id, lang, unit_key, ordinal, raw, lookup_path
)
SELECT b.id, t.lang, t.unit_key, t.ordinal, t.raw, t.lookup_path
FROM blobs_new AS b
CROSS JOIN unit_supertypes AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_children_new(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  parent_key  INTEGER NOT NULL,
  child_key   INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, parent_key, child_key, ordinal),
  CHECK(parent_key <> child_key),
  FOREIGN KEY(blob_id, parent_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, child_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_children_new(blob_id, lang, parent_key, child_key, ordinal)
SELECT b.id, t.lang, t.parent_key, t.child_key, t.ordinal
FROM blobs_new AS b
CROSS JOIN unit_children AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE unit_cpp_template_metadata_new(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  metadata BLOB    NOT NULL,
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO unit_cpp_template_metadata_new(blob_id, lang, unit_key, metadata)
SELECT b.id, t.lang, t.unit_key, t.metadata
FROM blobs_new AS b
CROSS JOIN unit_cpp_template_metadata AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE ruby_method_dispatch_modes_new(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  mode     INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO ruby_method_dispatch_modes_new(blob_id, lang, unit_key, mode)
SELECT b.id, t.lang, t.unit_key, t.mode
FROM blobs_new AS b
CROSS JOIN ruby_method_dispatch_modes AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE scala_traits_new(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  PRIMARY KEY(blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO scala_traits_new(blob_id, lang, unit_key)
SELECT b.id, t.lang, t.unit_key
FROM blobs_new AS b
CROSS JOIN scala_traits AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE scala_exports_new(
  blob_id    INTEGER NOT NULL,
  lang       TEXT    NOT NULL,
  owner_key  INTEGER NOT NULL,
  ordinal    INTEGER NOT NULL,
  info       BLOB    NOT NULL,
  PRIMARY KEY(blob_id, owner_key, ordinal),
  FOREIGN KEY(blob_id, owner_key)
    REFERENCES code_units_new(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO scala_exports_new(blob_id, lang, owner_key, ordinal, info)
SELECT b.id, t.lang, t.owner_key, t.ordinal, t.info
FROM blobs_new AS b
CROSS JOIN scala_exports AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE import_statements_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO import_statements_new(
  blob_id, lang, ordinal, statement, is_wildcard, is_global, identifier, alias,
  path_kind, declaration_start_byte, binder_start, binder_end
)
SELECT b.id, t.lang, t.ordinal, t.statement, t.is_wildcard, t.is_global,
       t.identifier, t.alias, t.path_kind, t.declaration_start_byte,
       t.binder_start, t.binder_end
FROM blobs_new AS b
CROSS JOIN import_statements AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE import_path_segments_new(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL CHECK(ordinal >= 0),
  seg_ordinal INTEGER NOT NULL CHECK(seg_ordinal >= 0),
  segment     TEXT    NOT NULL,
  PRIMARY KEY(blob_id, ordinal, seg_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES import_statements_new(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO import_path_segments_new(
  blob_id, lang, ordinal, seg_ordinal, segment
)
SELECT b.id, t.lang, t.ordinal, t.seg_ordinal, t.segment
FROM blobs_new AS b
CROSS JOIN import_path_segments AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE import_lexical_scopes_new(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL CHECK(ordinal >= 0),
  scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
  start_byte    INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte      INTEGER NOT NULL CHECK(end_byte >= 0),
  CHECK(start_byte <= end_byte),
  PRIMARY KEY(blob_id, ordinal, scope_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES import_statements_new(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO import_lexical_scopes_new(
  blob_id, lang, ordinal, scope_ordinal, start_byte, end_byte
)
SELECT b.id, t.lang, t.ordinal, t.scope_ordinal, t.start_byte, t.end_byte
FROM blobs_new AS b
CROSS JOIN import_lexical_scopes AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE import_lexical_prefixes_new(
  blob_id        INTEGER NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL CHECK(ordinal >= 0),
  prefix_ordinal INTEGER NOT NULL CHECK(prefix_ordinal >= 0),
  prefix         TEXT    NOT NULL,
  PRIMARY KEY(blob_id, ordinal, prefix_ordinal),
  FOREIGN KEY(blob_id, ordinal)
    REFERENCES import_statements_new(blob_id, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO import_lexical_prefixes_new(
  blob_id, lang, ordinal, prefix_ordinal, prefix
)
SELECT b.id, t.lang, t.ordinal, t.prefix_ordinal, t.prefix
FROM blobs_new AS b
CROSS JOIN import_lexical_prefixes AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE reference_identifiers_new(
  blob_id    INTEGER NOT NULL,
  lang       TEXT    NOT NULL,
  identifier TEXT    NOT NULL,
  PRIMARY KEY(blob_id, identifier),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO reference_identifiers_new(blob_id, lang, identifier)
SELECT b.id, t.lang, t.identifier
FROM blobs_new AS b
CROSS JOIN reference_identifiers AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE materialization_records_new(
  blob_id  INTEGER NOT NULL,
  lang     TEXT    NOT NULL,
  ordinal  INTEGER NOT NULL,
  unit_key INTEGER,
  payload  BLOB    NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO materialization_records_new(blob_id, lang, ordinal, unit_key, payload)
SELECT b.id, t.lang, t.ordinal, t.unit_key, t.payload
FROM blobs_new AS b
CROSS JOIN materialization_records AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE blob_meta_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_meta_new(
  blob_id, lang, contains_tests, content_package, stored_unit_count,
  range_count, signature_count, signature_metadata_count, supertype_count,
  child_count, import_statement_count, type_identifier_count, is_complete
)
SELECT b.id, t.lang, t.contains_tests, t.content_package, t.stored_unit_count,
       t.range_count, t.signature_count, t.signature_metadata_count,
       t.supertype_count, t.child_count, t.import_statement_count,
       t.type_identifier_count, t.is_complete
FROM blobs_new AS b
CROSS JOIN blob_meta AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE blob_optional_fact_manifest_new(
  blob_id    INTEGER NOT NULL,
  fact_kind  INTEGER NOT NULL CHECK(fact_kind > 0),
  row_count  INTEGER NOT NULL CHECK(row_count > 0),
  PRIMARY KEY(blob_id, fact_kind),
  FOREIGN KEY(blob_id)
    REFERENCES blob_meta_new(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_optional_fact_manifest_new(blob_id, fact_kind, row_count)
SELECT b.id, t.fact_kind, t.row_count
FROM blobs_new AS b
CROSS JOIN blob_optional_fact_manifest AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE blob_payload_costs_new(
  blob_id        INTEGER NOT NULL,
  payload_bytes  INTEGER NOT NULL CHECK(payload_bytes >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id)
    REFERENCES blob_meta_new(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_payload_costs_new(blob_id, payload_bytes)
SELECT b.id, t.payload_bytes
FROM blobs_new AS b
CROSS JOIN blob_payload_costs AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE structural_facts_snapshots_new(
  blob_id           INTEGER NOT NULL,
  snapshot_version  INTEGER NOT NULL CHECK(snapshot_version > 0),
  payload           BLOB    NOT NULL,
  PRIMARY KEY(blob_id, snapshot_version),
  FOREIGN KEY(blob_id)
    REFERENCES blob_meta_new(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO structural_facts_snapshots_new(blob_id, snapshot_version, payload)
SELECT b.id, t.snapshot_version, t.payload
FROM blobs_new AS b
CROSS JOIN structural_facts_snapshots AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE blob_reference_fact_manifests_new(
  blob_id           INTEGER NOT NULL,
  lang              TEXT    NOT NULL,
  epoch             INTEGER NOT NULL CHECK(epoch > 0),
  identifier_count  INTEGER NOT NULL CHECK(identifier_count >= 0),
  PRIMARY KEY(blob_id),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_reference_fact_manifests_new(
  blob_id, lang, epoch, identifier_count
)
SELECT b.id, t.lang, t.epoch, t.identifier_count
FROM blobs_new AS b
CROSS JOIN blob_reference_fact_manifests AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_exports_new(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  exported_name TEXT,
  source_path   TEXT    NOT NULL,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_exports_new(
  blob_id, lang, ordinal, exported_name, source_path, imported_name, is_glob
)
SELECT b.id, t.lang, t.ordinal, t.exported_name, t.source_path,
       t.imported_name, t.is_glob
FROM blobs_new AS b
CROSS JOIN rust_exports AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_import_targets_new(
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
  is_extern_crate INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_import_targets_new(
  blob_id, lang, ordinal, module_path, bound_name, imported_name, is_glob,
  visibility, owner_module, owner_start, owner_end, local_start, local_end,
  cfg_condition, is_extern_crate
)
SELECT b.id, t.lang, t.ordinal, t.module_path, t.bound_name, t.imported_name,
       t.is_glob, t.visibility, t.owner_module, t.owner_start, t.owner_end,
       t.local_start, t.local_end, t.cfg_condition, t.is_extern_crate
FROM blobs_new AS b
CROSS JOIN rust_import_targets AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_modules_new(
  blob_id     INTEGER NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  module_name TEXT    NOT NULL,
  is_inline   INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_modules_new(
  blob_id, lang, ordinal, module_name, is_inline, start_byte, end_byte
)
SELECT b.id, t.lang, t.ordinal, t.module_name, t.is_inline, t.start_byte,
       t.end_byte
FROM blobs_new AS b
CROSS JOIN rust_modules AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_identifier_occurrences_new(
  blob_id      INTEGER NOT NULL,
  lang         TEXT    NOT NULL,
  identifier   TEXT    NOT NULL,
  context_mask INTEGER NOT NULL,
  PRIMARY KEY(blob_id, identifier),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_identifier_occurrences_new(
  blob_id, lang, identifier, context_mask
)
SELECT b.id, t.lang, t.identifier, t.context_mask
FROM blobs_new AS b
CROSS JOIN rust_identifier_occurrences AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_module_scopes_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_module_scopes_new(
  blob_id, lang, ordinal, parent_ordinal, module_name, path_attribute,
  imports_macros, body_start, body_end
)
SELECT b.id, t.lang, t.ordinal, t.parent_ordinal, t.module_name,
       t.path_attribute, t.imports_macros, t.body_start, t.body_end
FROM blobs_new AS b
CROSS JOIN rust_module_scopes AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_module_routes_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_module_routes_new(
  blob_id, lang, ordinal, scope_ordinal, module_name, path_attribute,
  visibility, imports_macros, test_gated, declaration_start, declaration_end
)
SELECT b.id, t.lang, t.ordinal, t.scope_ordinal, t.module_name,
       t.path_attribute, t.visibility, t.imports_macros, t.test_gated,
       t.declaration_start, t.declaration_end
FROM blobs_new AS b
CROSS JOIN rust_module_routes AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_module_route_gates_new(
  blob_id          INTEGER NOT NULL,
  lang             TEXT    NOT NULL,
  route_ordinal    INTEGER NOT NULL,
  gate_ordinal     INTEGER NOT NULL,
  macro_name       TEXT    NOT NULL,
  invocation_start INTEGER NOT NULL,
  PRIMARY KEY(blob_id, route_ordinal, gate_ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_module_route_gates_new(
  blob_id, lang, route_ordinal, gate_ordinal, macro_name, invocation_start
)
SELECT b.id, t.lang, t.route_ordinal, t.gate_ordinal, t.macro_name,
       t.invocation_start
FROM blobs_new AS b
CROSS JOIN rust_module_route_gates AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_item_macros_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_item_macros_new(
  blob_id, lang, ordinal, macro_name, visible_after, scope_start, scope_end,
  passthrough
)
SELECT b.id, t.lang, t.ordinal, t.macro_name, t.visible_after, t.scope_start,
       t.scope_end, t.passthrough
FROM blobs_new AS b
CROSS JOIN rust_item_macros AS t ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_include_edges_new(
  blob_id       INTEGER NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  relative_path TEXT    NOT NULL,
  file_name     TEXT    NOT NULL,
  include_start INTEGER NOT NULL,
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id, lang)
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_include_edges_new(
  blob_id, lang, ordinal, relative_path, file_name, include_start
)
SELECT b.id, t.lang, t.ordinal, t.relative_path, t.file_name, t.include_start
FROM blobs_new AS b
CROSS JOIN rust_include_edges AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

CREATE TABLE rust_include_host_bindings_new(
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
    REFERENCES blobs_new(id, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_include_host_bindings_new(
  blob_id, lang, edge_ordinal, ordinal, local_name, module_specifier,
  imported_name, scope_start, kind
)
SELECT b.id, t.lang, t.edge_ordinal, t.ordinal, t.local_name,
       t.module_specifier, t.imported_name, t.scope_start, t.kind
FROM blobs_new AS b
CROSS JOIN rust_include_host_bindings AS t
  ON t.blob_oid = b.blob_oid AND t.lang = b.lang;

-- Children before parents: under `PRAGMA foreign_keys = ON` a DROP performs an
-- implicit DELETE, which would cascade into a table that has not been dropped
-- yet.
DROP TABLE code_unit_fq_segments;
DROP TABLE unit_visibility_containers;
DROP TABLE unit_ranges;
DROP TABLE unit_signatures;
DROP TABLE unit_signature_metadata;
DROP TABLE unit_supertypes;
DROP TABLE unit_children;
DROP TABLE unit_cpp_template_metadata;
DROP TABLE ruby_method_dispatch_modes;
DROP TABLE scala_traits;
DROP TABLE scala_exports;
DROP TABLE code_units;
DROP TABLE import_path_segments;
DROP TABLE import_lexical_scopes;
DROP TABLE import_lexical_prefixes;
DROP TABLE import_statements;
DROP TABLE blob_optional_fact_manifest;
DROP TABLE blob_payload_costs;
DROP TABLE structural_facts_snapshots;
DROP TABLE blob_meta;
DROP TABLE blob_reference_fact_manifests;
DROP TABLE reference_identifiers;
DROP TABLE materialization_records;
DROP TABLE rust_exports;
DROP TABLE rust_import_targets;
DROP TABLE rust_modules;
DROP TABLE rust_identifier_occurrences;
DROP TABLE rust_module_scopes;
DROP TABLE rust_module_routes;
DROP TABLE rust_module_route_gates;
DROP TABLE rust_item_macros;
DROP TABLE rust_include_edges;
DROP TABLE rust_include_host_bindings;
DROP TABLE blobs;

ALTER TABLE blobs_new RENAME TO blobs;
ALTER TABLE code_units_new RENAME TO code_units;
ALTER TABLE code_unit_fq_segments_new RENAME TO code_unit_fq_segments;
ALTER TABLE unit_visibility_containers_new RENAME TO unit_visibility_containers;
ALTER TABLE unit_ranges_new RENAME TO unit_ranges;
ALTER TABLE unit_signatures_new RENAME TO unit_signatures;
ALTER TABLE unit_signature_metadata_new RENAME TO unit_signature_metadata;
ALTER TABLE unit_supertypes_new RENAME TO unit_supertypes;
ALTER TABLE unit_children_new RENAME TO unit_children;
ALTER TABLE unit_cpp_template_metadata_new RENAME TO unit_cpp_template_metadata;
ALTER TABLE ruby_method_dispatch_modes_new RENAME TO ruby_method_dispatch_modes;
ALTER TABLE scala_traits_new RENAME TO scala_traits;
ALTER TABLE scala_exports_new RENAME TO scala_exports;
ALTER TABLE import_statements_new RENAME TO import_statements;
ALTER TABLE import_path_segments_new RENAME TO import_path_segments;
ALTER TABLE import_lexical_scopes_new RENAME TO import_lexical_scopes;
ALTER TABLE import_lexical_prefixes_new RENAME TO import_lexical_prefixes;
ALTER TABLE reference_identifiers_new RENAME TO reference_identifiers;
ALTER TABLE materialization_records_new RENAME TO materialization_records;
ALTER TABLE blob_meta_new RENAME TO blob_meta;
ALTER TABLE blob_optional_fact_manifest_new RENAME TO blob_optional_fact_manifest;
ALTER TABLE blob_payload_costs_new RENAME TO blob_payload_costs;
ALTER TABLE structural_facts_snapshots_new RENAME TO structural_facts_snapshots;
ALTER TABLE blob_reference_fact_manifests_new RENAME TO blob_reference_fact_manifests;
ALTER TABLE rust_exports_new RENAME TO rust_exports;
ALTER TABLE rust_import_targets_new RENAME TO rust_import_targets;
ALTER TABLE rust_modules_new RENAME TO rust_modules;
ALTER TABLE rust_identifier_occurrences_new RENAME TO rust_identifier_occurrences;
ALTER TABLE rust_module_scopes_new RENAME TO rust_module_scopes;
ALTER TABLE rust_module_routes_new RENAME TO rust_module_routes;
ALTER TABLE rust_module_route_gates_new RENAME TO rust_module_route_gates;
ALTER TABLE rust_item_macros_new RENAME TO rust_item_macros;
ALTER TABLE rust_include_edges_new RENAME TO rust_include_edges;
ALTER TABLE rust_include_host_bindings_new RENAME TO rust_include_host_bindings;

-- The index set is unchanged in columns and in purpose. The seven entries that
-- named `blob_oid` name `blob_id`; the rest are recreated verbatim because
-- dropping a table drops its indexes.
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

-- `live_parsed_blobs` is the intern point on the read side: it exposes the id
-- every downstream join uses AND the hex the workspace projections still store,
-- so no view gains a join it did not have before this migration.
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
