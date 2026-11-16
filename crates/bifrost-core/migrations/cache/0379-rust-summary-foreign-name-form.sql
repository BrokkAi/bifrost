-- #11173 walk slice 3: a Rust summary stores no coordinate of another unit's rows.
--
-- Compatible: the two tables hold derived cache rows. The Rust unit summary
-- derivation version moves with this migration, so no existing summary is reused
-- and every one is derived again into the new shapes; a build of an older version
-- keeps its own version-suffixed store file. They are dropped and recreated because
-- SQLite cannot drop a column that a table CHECK names.
--
-- effective_bindings: a `mod` binding stored the declaration id of a foreign module
-- item (target_declaration_key), a per-blob coordinate that moves when the declaring
-- file is edited without changing any name. The row already carries the name form of
-- its target (target_unit_key, target_module_path, target_name), which names the
-- module item, so the declaration key is dropped. A binding has no identity exactly
-- when its namespace is 'module'.
--
-- import_route_provenance: target_route_provenance_ordinal copied another unit's
-- insertion counter, which depends on that unit's member order and binding count,
-- and nothing reads it: the reader follows the name form (target_unit_key,
-- target_binding_module_path, target_binding_name, namespace). It is dropped from
-- the row and from the key, and so is the declaration key, for the same reason as above.
DROP TABLE rust_resolution_unit_summary_import_route_provenance;
DROP TABLE rust_resolution_unit_summary_effective_bindings;

CREATE TABLE rust_resolution_unit_summary_effective_bindings (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  module_path TEXT NOT NULL,
  binder_scope INTEGER NOT NULL CHECK(binder_scope >= -1),
  name TEXT NOT NULL CHECK(length(name) > 0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro', 'module')),
  visibility_kind TEXT NOT NULL CHECK(visibility_kind IN ('public', 'crate', 'module')),
  visibility_crate_root TEXT,
  visibility_module_path TEXT,
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  target_identity_id INTEGER REFERENCES resolution_identities(id),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL CHECK(length(target_name) > 0),
  route_provenance_ordinal INTEGER NOT NULL CHECK(route_provenance_ordinal >= 0),
  source_import_id INTEGER CHECK(source_import_id IS NULL OR source_import_id >= 0),
  source_import_ordinal INTEGER CHECK(source_import_ordinal IS NULL OR source_import_ordinal >= 0),
  PRIMARY KEY(summary_id, member_ordinal, module_path, binder_scope, name, namespace,
              target_unit_key, route_provenance_ordinal),
  CHECK((visibility_kind = 'public' AND visibility_crate_root IS NULL
         AND visibility_module_path IS NULL)
     OR (visibility_kind = 'crate' AND visibility_crate_root IS NOT NULL
         AND visibility_module_path IS NULL)
     OR (visibility_kind = 'module' AND visibility_crate_root IS NOT NULL
         AND visibility_module_path IS NOT NULL)),
  CHECK((namespace = 'module') = (target_identity_id IS NULL)),
  CHECK((source_import_id IS NULL) = (source_import_ordinal IS NULL)),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_resolution_unit_summary_effective_bindings_identity
  ON rust_resolution_unit_summary_effective_bindings(
    target_unit_key, target_identity_id, summary_id, member_ordinal);

CREATE INDEX rust_resolution_unit_summary_effective_bindings_member_name
  ON rust_resolution_unit_summary_effective_bindings(
    summary_id, member_ordinal, module_path, name, namespace);

CREATE INDEX rust_resolution_unit_summary_effective_bindings_module_name
  ON rust_resolution_unit_summary_effective_bindings(
    summary_id, module_path, name, namespace);

CREATE UNIQUE INDEX rust_resolution_unit_summary_effective_bindings_route
  ON rust_resolution_unit_summary_effective_bindings(summary_id, route_provenance_ordinal);

CREATE INDEX rust_resolution_unit_summary_effective_bindings_target
  ON rust_resolution_unit_summary_effective_bindings(
    target_unit_key, target_module_path, target_name, namespace,
    summary_id, module_path, member_ordinal);

CREATE TABLE rust_resolution_unit_summary_import_route_provenance (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  import_id INTEGER NOT NULL CHECK(import_id >= 0),
  import_ordinal INTEGER NOT NULL CHECK(import_ordinal >= 0),
  route_provenance_ordinal INTEGER NOT NULL CHECK(route_provenance_ordinal >= 0),
  hop_ordinal INTEGER NOT NULL CHECK(hop_ordinal >= 0),
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  target_binding_module_path TEXT NOT NULL,
  target_binding_name TEXT NOT NULL CHECK(length(target_binding_name) > 0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro', 'module')),
  target_identity_id INTEGER REFERENCES resolution_identities(id),
  CHECK((namespace = 'module') = (target_identity_id IS NULL)),
  -- One import route can reach the same alias binding through two traversed
  -- bindings of its target: the target module binds one name twice (an explicit
  -- re-export that shadows a glob, both reaching one declaration). They are one
  -- name-level fact, so the route's key is the traversed binding's name form.
  PRIMARY KEY(summary_id, member_ordinal, import_ordinal,
              route_provenance_ordinal, hop_ordinal,
              target_unit_key, target_binding_module_path, target_binding_name, namespace),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_binding
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, route_provenance_ordinal, hop_ordinal, target_unit_key);

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_owner
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, member_ordinal, import_id, import_ordinal,
    route_provenance_ordinal, hop_ordinal);

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_target
  ON rust_resolution_unit_summary_import_route_provenance(
    target_unit_key, target_binding_module_path, target_binding_name, namespace,
    summary_id, member_ordinal, import_ordinal);
