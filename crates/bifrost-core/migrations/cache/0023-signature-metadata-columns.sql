-- One declaration signature, one row of typed columns.
--
-- `unit_signature_metadata` used to hold a bincode-serialized `SignatureMetadata`
-- in a single BLOB column. Bincode writes fields in declaration order with no
-- names and no tags, so the layout was invisible to the database and to every
-- reader that was not this exact build: adding one field to the struct changed
-- the byte layout, and rows written before that field existed could no longer be
-- decoded. The only defense was the store epoch salt, a version string hashed
-- into every cache generation, and bumping it invalidates every analyzer row for
-- every language in every cache on every machine. This one struct forced three
-- of the seven recorded salt turnovers. It is also the largest non-exempt blob
-- store measured: 2,017,642 rows totaling 409.1 MB in a gcc cache, 256,260 rows
-- totaling 50.8 MB in a kubernetes cache.
--
-- The rule for every future signature fact: add a column here with a DEFAULT, in
-- a new migration, and leave the salt alone. Never add a field to a serialized
-- struct. An additive column costs one migration and invalidates nothing,
-- because SQLite fills existing rows from the default. This is the same trade
-- `0019-import-bindings.sql` made for imports, which caused salt turnovers v7,
-- v8, and v9 before it and none after it.
--
-- A version-23 build opens `bifrost_cache.v23.db`, a fresh file, and runs the
-- whole chain 0018..0023 against an empty database, so the DROP below always
-- drops an empty table. There is never data to convert. The v22 file is left
-- untouched beside it and ages out through the existing version-store grace
-- collection.
DROP TABLE unit_signature_metadata;

-- Scalars and enums are columns. The three `StructuredTypeIdentity` values and
-- the two string lists are JSON text, because they are recursive or open shapes
-- that no SQL query wants to look inside today, and serde's JSON form is
-- self-describing, so additive changes to those types also stop forcing epoch
-- bumps. When a second reader wants a field out of one of them, promote that
-- field to a generated column and index it rather than decoding the JSON in
-- Rust.
--
-- The byte caps are the write-time admission gate. They replace read-side
-- `CASE WHEN length(metadata) <= N THEN metadata ELSE NULL END` clauses that
-- silently nulled an oversized row long after it was stored; an oversized row
-- now fails to insert, loudly, at the point of construction. 8388608 is
-- `MAX_SIGNATURE_METADATA_BLOB_BYTES` in
-- `crates/bifrost-core/src/analyzer/model.rs`; a const assertion in
-- `crates/bifrost-core/src/cache_db.rs` keeps the two spellings equal.
-- `length(CAST(x AS BLOB))` counts bytes; bare `length()` on TEXT counts
-- characters, which is not the budget anyone means.
--
-- `callable_parameter_types` distinguishes NULL from '[]' on purpose: NULL means
-- the language adapter records no per-parameter type at all, '[]' means a
-- proven-empty parameter list. An overload discriminator must not confuse the
-- two.
--
-- The callable arity trio is one nullable value spread over three columns, so a
-- table-level CHECK keeps them all-present or all-absent rather than letting a
-- half-written arity exist.
CREATE TABLE unit_signature_metadata(
  blob_oid                            TEXT    NOT NULL,
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
  PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
