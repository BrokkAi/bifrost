-- Preserve every canonical Rust endpoint; these are derived crate/summary rows.

PRAGMA legacy_alter_table=ON;

CREATE TABLE rust_crate_exports_new(
  topology_id             INTEGER NOT NULL,
  module_path             TEXT NOT NULL,
  namespace               TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro')),
  name                    TEXT NOT NULL CHECK(length(name) > 0),
  origin                  TEXT NOT NULL CHECK(origin IN ('declaration', 'reexport', 'glob_reexport')),
  visibility              TEXT NOT NULL CHECK(visibility IN ('public', 'crate', 'restricted', 'private')),
  restricted_module_path  TEXT CHECK(restricted_module_path IS NULL OR restricted_module_path LIKE 'crate%'),
  declaration_blob_id     INTEGER NOT NULL,
  declaration_site        INTEGER NOT NULL CHECK(declaration_site >= 0),   -- resolution_semantic_sites.source_site
  target_crate_key BLOB NOT NULL DEFAULT X'',
  target_module_path TEXT NOT NULL DEFAULT '',
  target_name TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(topology_id, module_path, namespace, name,target_crate_key,target_module_path,target_name),
  CHECK((visibility = 'restricted') = (restricted_module_path IS NOT NULL)),
  FOREIGN KEY(topology_id, module_path) REFERENCES rust_crate_containers(topology_id, container_path) ON DELETE CASCADE,
  FOREIGN KEY(declaration_blob_id) REFERENCES blobs(id)
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_exports_new SELECT exports.*,topology.crate_key,exports.module_path,exports.name FROM rust_crate_exports exports JOIN rust_crate_topologies topology USING(topology_id);

DROP TABLE rust_crate_exports;

ALTER TABLE rust_crate_exports_new RENAME TO rust_crate_exports;

CREATE INDEX rust_crate_exports_declaration
  ON rust_crate_exports(declaration_blob_id, declaration_site, topology_id, module_path, namespace, name);

CREATE TABLE rust_crate_imports_new(
  topology_id           INTEGER NOT NULL,
  module_path           TEXT NOT NULL,
  namespace             TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro')),
  bound_name            TEXT NOT NULL CHECK(length(bound_name) > 0),
  blob_id               INTEGER NOT NULL REFERENCES blobs(id),
  import_ordinal        INTEGER NOT NULL CHECK(import_ordinal >= 0),   -- source_rust_import_targets.ordinal in the module's blob
  binder_scope          INTEGER NOT NULL CHECK(binder_scope >= 0),     -- blob-local ResolutionScopeId the binder lives in
  target_crate_key      BLOB NOT NULL
    CHECK(typeof(target_crate_key) = 'blob' AND length(target_crate_key) = 32),
  target_module_path    TEXT NOT NULL,
  target_name           TEXT NOT NULL,
  PRIMARY KEY(topology_id, module_path, blob_id, binder_scope, namespace, bound_name, target_crate_key, target_module_path, target_name),
  FOREIGN KEY(topology_id, module_path) REFERENCES rust_crate_containers(topology_id, container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_imports_new SELECT * FROM rust_crate_imports;

DROP TABLE rust_crate_imports;

ALTER TABLE rust_crate_imports_new RENAME TO rust_crate_imports;

CREATE INDEX rust_crate_imports_binder
  ON rust_crate_imports(topology_id, module_path, blob_id, binder_scope, bound_name);

CREATE INDEX rust_crate_imports_target
  ON rust_crate_imports(target_crate_key, target_module_path, target_name, topology_id, module_path, namespace, bound_name);

CREATE TABLE rust_crate_glob_imports_new(
  topology_id           INTEGER NOT NULL,
  module_path           TEXT NOT NULL,
  blob_id               INTEGER NOT NULL REFERENCES blobs(id),
  import_ordinal        INTEGER NOT NULL CHECK(import_ordinal >= 0),
  binder_scope          INTEGER NOT NULL CHECK(binder_scope >= 0),
  target_crate_key      BLOB NOT NULL
    CHECK(typeof(target_crate_key) = 'blob' AND length(target_crate_key) = 32),
  target_module_path    TEXT NOT NULL,
  PRIMARY KEY(topology_id, module_path, blob_id, binder_scope, import_ordinal, target_crate_key, target_module_path),
  FOREIGN KEY(topology_id, module_path) REFERENCES rust_crate_containers(topology_id, container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_glob_imports_new SELECT * FROM rust_crate_glob_imports;

DROP TABLE rust_crate_glob_imports;

ALTER TABLE rust_crate_glob_imports_new RENAME TO rust_crate_glob_imports;

CREATE INDEX rust_crate_glob_imports_target
  ON rust_crate_glob_imports(target_crate_key, target_module_path, topology_id, module_path);

CREATE TABLE rust_crate_root_references_new(
  topology_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  blob_id INTEGER NOT NULL,
  path_key INTEGER NOT NULL,
  reference_source_site INTEGER NOT NULL
    CHECK(reference_source_site BETWEEN 0 AND 4294967295),
  target_crate_key BLOB NOT NULL
    CHECK(typeof(target_crate_key) = 'blob' AND length(target_crate_key)=32),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL,
  PRIMARY KEY(topology_id, module_path, blob_id, path_key, target_crate_key, target_module_path, target_name),
  FOREIGN KEY(topology_id, module_path, blob_id)
    REFERENCES rust_crate_container_members(topology_id, container_path, blob_id)
    ON DELETE CASCADE,
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_crate_root_references_new SELECT * FROM rust_crate_root_references;

DROP TABLE rust_crate_root_references;

ALTER TABLE rust_crate_root_references_new RENAME TO rust_crate_root_references;

CREATE INDEX rust_crate_root_references_target
  ON rust_crate_root_references(
    target_crate_key, target_module_path, target_name,
    topology_id, module_path, blob_id, path_key, reference_source_site
  );

CREATE TABLE rust_resolution_unit_summary_exports_new (
  summary_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro')),
  name TEXT NOT NULL CHECK(length(name) > 0),
  identity_id INTEGER NOT NULL REFERENCES resolution_identities(id),
  visibility TEXT NOT NULL CHECK(visibility IN ('public', 'crate', 'restricted', 'private')),
  restricted_module_path TEXT
    CHECK(restricted_module_path IS NULL OR restricted_module_path LIKE 'crate%'),
  origin TEXT NOT NULL CHECK(origin IN ('declaration', 'reexport', 'glob_reexport')),
  declaration_member_ordinal INTEGER CHECK(
    declaration_member_ordinal IS NULL OR declaration_member_ordinal >= 0),
  declaration_site INTEGER CHECK(declaration_site IS NULL OR declaration_site BETWEEN 0 AND 4294967295),
  alias_dependency_ordinal INTEGER CHECK(
    alias_dependency_ordinal IS NULL OR alias_dependency_ordinal >= 0),
  target_unit_key BLOB CHECK(target_unit_key IS NULL OR
    (typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32)),
  alias_identity_id INTEGER REFERENCES resolution_identities(id),
  target_module_path TEXT,
  target_name TEXT,
  CHECK((visibility = 'restricted') = (restricted_module_path IS NOT NULL)),
  CHECK((declaration_member_ordinal IS NULL) = (declaration_site IS NULL)),
  CHECK(origin <> 'declaration' OR
        (alias_dependency_ordinal IS NULL AND alias_identity_id IS NULL
         AND target_unit_key IS NULL AND target_module_path IS NULL AND target_name IS NULL)),
  CHECK(origin = 'declaration' OR
        (target_unit_key IS NOT NULL AND alias_identity_id IS NOT NULL
         AND target_module_path IS NOT NULL AND target_name IS NOT NULL)),
  CHECK((target_module_path IS NULL) = (target_name IS NULL)),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, declaration_member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) STRICT;

INSERT INTO rust_resolution_unit_summary_exports_new SELECT * FROM rust_resolution_unit_summary_exports;

DROP TABLE rust_resolution_unit_summary_exports;

ALTER TABLE rust_resolution_unit_summary_exports_new RENAME TO rust_resolution_unit_summary_exports;

CREATE INDEX rust_resolution_unit_summary_exports_alias_target
  ON rust_resolution_unit_summary_exports(
    target_unit_key, target_module_path, target_name, namespace, alias_identity_id,
    summary_id, module_path, name, identity_id, visibility)
  WHERE origin <> 'declaration';

CREATE INDEX rust_resolution_unit_summary_exports_declaration
  ON rust_resolution_unit_summary_exports(
    summary_id, declaration_member_ordinal, declaration_site, namespace, module_path)
  WHERE origin = 'declaration';

CREATE INDEX rust_resolution_unit_summary_exports_identity
  ON rust_resolution_unit_summary_exports(summary_id, identity_id, namespace);

CREATE INDEX rust_resolution_unit_summary_exports_name
  ON rust_resolution_unit_summary_exports(name, namespace, visibility, summary_id, module_path);

CREATE UNIQUE INDEX rust_summary_decl_export_endpoint ON rust_resolution_unit_summary_exports(summary_id,module_path,namespace,name,declaration_member_ordinal,declaration_site) WHERE origin='declaration';

CREATE UNIQUE INDEX rust_summary_alias_export_endpoint ON rust_resolution_unit_summary_exports(summary_id,module_path,namespace,name,target_unit_key,target_module_path,target_name) WHERE origin<>'declaration';

CREATE TABLE rust_resolution_unit_summary_import_routes_new (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  import_id INTEGER NOT NULL CHECK(import_id >= 0),
  route_ordinal INTEGER NOT NULL CHECK(route_ordinal >= 0),
  module_path TEXT NOT NULL,
  binder_scope INTEGER NOT NULL CHECK(binder_scope >= 0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro')),
  bound_name TEXT NOT NULL CHECK(length(bound_name) > 0),
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL CHECK(length(target_name) > 0),
  PRIMARY KEY(summary_id, member_ordinal, import_id, route_ordinal, module_path,
              binder_scope, namespace, bound_name, target_unit_key, target_module_path, target_name),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_resolution_unit_summary_import_routes_new SELECT * FROM rust_resolution_unit_summary_import_routes;

DROP TABLE rust_resolution_unit_summary_import_routes;

ALTER TABLE rust_resolution_unit_summary_import_routes_new RENAME TO rust_resolution_unit_summary_import_routes;

CREATE INDEX rust_resolution_unit_summary_import_routes_binder
  ON rust_resolution_unit_summary_import_routes(
    summary_id, member_ordinal, binder_scope, namespace, bound_name, import_id, route_ordinal);

CREATE INDEX rust_resolution_unit_summary_import_routes_site
  ON rust_resolution_unit_summary_import_routes(
    summary_id, member_ordinal, import_id, route_ordinal, module_path, namespace);

CREATE INDEX rust_resolution_unit_summary_import_routes_target
  ON rust_resolution_unit_summary_import_routes(
    summary_id, dependency_ordinal, target_module_path, target_name, namespace);

CREATE INDEX rust_resolution_unit_summary_import_routes_target_identity
  ON rust_resolution_unit_summary_import_routes(
    target_unit_key, target_module_path, target_name, namespace,
    summary_id, module_path, bound_name);

CREATE TABLE rust_resolution_unit_summary_glob_imports_new (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  source_import_id INTEGER NOT NULL CHECK(source_import_id >= 0),
  route_ordinal INTEGER NOT NULL CHECK(route_ordinal >= 0),
  module_path TEXT NOT NULL,
  binder_scope INTEGER NOT NULL CHECK(binder_scope >= 0),
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
  target_module_path TEXT NOT NULL,
  PRIMARY KEY(summary_id, member_ordinal, source_import_id, route_ordinal,
              module_path, binder_scope, target_unit_key, target_module_path),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_resolution_unit_summary_glob_imports_new SELECT * FROM rust_resolution_unit_summary_glob_imports;

DROP TABLE rust_resolution_unit_summary_glob_imports;

ALTER TABLE rust_resolution_unit_summary_glob_imports_new RENAME TO rust_resolution_unit_summary_glob_imports;

CREATE INDEX rust_resolution_unit_summary_glob_imports_target
  ON rust_resolution_unit_summary_glob_imports(
    summary_id, dependency_ordinal, target_module_path, module_path);

CREATE INDEX rust_resolution_unit_summary_glob_imports_target_identity
  ON rust_resolution_unit_summary_glob_imports(
    target_unit_key, target_module_path, summary_id, module_path, member_ordinal,
    binder_scope, source_import_id);

CREATE TABLE rust_resolution_unit_summary_root_routes_new (
  root_route_id INTEGER PRIMARY KEY,
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  module_path TEXT NOT NULL CHECK(module_path = 'crate' OR module_path LIKE 'crate::%'),
  route_key INTEGER NOT NULL CHECK(route_key >= 0),
  reference_source_site INTEGER NOT NULL CHECK(reference_source_site BETWEEN 0 AND 4294967295),
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  target_module_path TEXT NOT NULL CHECK(target_module_path = 'crate' OR target_module_path LIKE 'crate::%'),
  target_name TEXT NOT NULL CHECK(length(target_name) > 0),
  UNIQUE(summary_id, member_ordinal, module_path, route_key,target_unit_key,target_module_path,target_name),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path, member_ordinal)
    REFERENCES rust_resolution_unit_summary_placement_attributes(summary_id, module_path, member_ordinal)
    ON DELETE CASCADE
) STRICT;

INSERT INTO rust_resolution_unit_summary_root_routes_new SELECT * FROM rust_resolution_unit_summary_root_routes;

DROP TABLE rust_resolution_unit_summary_root_routes;

ALTER TABLE rust_resolution_unit_summary_root_routes_new RENAME TO rust_resolution_unit_summary_root_routes;

CREATE INDEX rust_resolution_unit_summary_root_routes_owner
  ON rust_resolution_unit_summary_root_routes(
    summary_id, member_ordinal, module_path, reference_source_site);

CREATE INDEX rust_resolution_unit_summary_root_routes_target
  ON rust_resolution_unit_summary_root_routes(
    target_unit_key, target_module_path, target_name);

PRAGMA legacy_alter_table=OFF;

-- Admitted first-hop dependencies are distinct from canonical publication.
-- A binding can reach one endpoint through several different providers.
CREATE TABLE rust_crate_binding_provenance(
  topology_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  blob_id INTEGER NOT NULL REFERENCES blobs(id),
  binder_scope INTEGER NOT NULL CHECK(binder_scope >= 0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'macro')),
  bound_name TEXT NOT NULL CHECK(length(bound_name) > 0),
  import_ordinal INTEGER NOT NULL CHECK(import_ordinal >= 0),
  provider_crate_key BLOB NOT NULL CHECK(length(provider_crate_key) = 32),
  provider_module_path TEXT NOT NULL,
  provider_blob_id INTEGER NOT NULL,
  provider_binder_scope INTEGER NOT NULL,
  provider_name TEXT NOT NULL CHECK(length(provider_name) > 0),
  target_crate_key BLOB NOT NULL CHECK(length(target_crate_key) = 32),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL,
  PRIMARY KEY(topology_id,module_path,blob_id,binder_scope,namespace,bound_name,
              import_ordinal,provider_crate_key,provider_module_path,provider_blob_id,
              provider_binder_scope,provider_name,
              target_crate_key,target_module_path,target_name),
  FOREIGN KEY(topology_id,module_path)
    REFERENCES rust_crate_containers(topology_id,container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_crate_binding_provenance_source
  ON rust_crate_binding_provenance(topology_id,blob_id,import_ordinal,namespace,
       target_crate_key,target_module_path,target_name);
