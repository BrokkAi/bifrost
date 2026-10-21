-- Placement and name bindings are unit-summary outputs, shared across languages.
CREATE TABLE resolution_unit_summary_containers (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 container_path TEXT NOT NULL,
 parent_container_path TEXT,
 PRIMARY KEY(summary_id, container_path),
 CHECK((container_path = '') = (parent_container_path IS NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_unit_summary_placements (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_ordinal INTEGER CHECK(scope_ordinal IS NULL OR scope_ordinal >= 0),
 PRIMARY KEY(summary_id, container_path, member_ordinal),
 FOREIGN KEY(summary_id, container_path) REFERENCES resolution_unit_summary_containers(summary_id, container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id, member_ordinal) REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- MODULES, MODULES_FOR_BLOB and reverse export readers start at a member.
CREATE INDEX resolution_unit_summary_placements_member
 ON resolution_unit_summary_placements(summary_id, member_ordinal, container_path);
CREATE TABLE resolution_unit_summary_dependency_names (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(length(role) > 0),
 name TEXT NOT NULL CHECK(length(name) > 0),
 dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
 PRIMARY KEY(summary_id, role, name)
) WITHOUT ROWID, STRICT;
-- REVERSE_EXPORTED_NAMES and importing-files readers enumerate aliases of a dependency.
CREATE INDEX resolution_unit_summary_dependency_names_ordinal
 ON resolution_unit_summary_dependency_names(summary_id, dependency_ordinal, name);
-- DEPENDENCY_BOUNDARY and OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL seek an
-- extern name in an owning summary.
CREATE INDEX resolution_unit_summary_dependency_names_owner_name
 ON resolution_unit_summary_dependency_names(summary_id, name, dependency_ordinal);
-- GAP_CANDIDATE_SITES_SQL seeks all owners of a dependency spelling.
CREATE INDEX resolution_unit_summary_dependency_names_name
 ON resolution_unit_summary_dependency_names(name, summary_id, dependency_ordinal);
CREATE TABLE rust_resolution_unit_summary_container_attributes (
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 module_path TEXT GENERATED ALWAYS AS (CASE container_path WHEN '' THEN 'crate' ELSE container_path END) VIRTUAL,
 kind TEXT NOT NULL CHECK(kind IN ('module', 'enum')),
 PRIMARY KEY(summary_id, container_path),
 UNIQUE(summary_id, module_path),
 FOREIGN KEY(summary_id, container_path) REFERENCES resolution_unit_summary_containers(summary_id, container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE rust_resolution_unit_summary_placement_attributes (
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 module_path TEXT GENERATED ALWAYS AS (CASE container_path WHEN '' THEN 'crate' ELSE container_path END) VIRTUAL,
 placement TEXT NOT NULL CHECK(placement IN ('root','mod_declaration','path_attribute','inline','enum_declaration')),
 source_kind TEXT NOT NULL CHECK(source_kind IN ('declared','include')),
 enum_scope_node_key INTEGER CHECK(enum_scope_node_key IS NULL OR enum_scope_node_key >= 0),
 PRIMARY KEY(summary_id, container_path, member_ordinal),
 UNIQUE(summary_id, module_path, member_ordinal),
 CHECK((placement = 'enum_declaration') = (enum_scope_node_key IS NOT NULL)),
 FOREIGN KEY(summary_id, container_path, member_ordinal) REFERENCES resolution_unit_summary_placements(summary_id, container_path, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- Rust's canonical route spelling is language data. These projections keep it
-- at the Rust boundary; generic rows use the empty unit-root path.
CREATE VIEW rust_unit_summary_containers AS
 SELECT c.summary_id, a.module_path, a.kind
 FROM resolution_unit_summary_containers AS c
 JOIN rust_resolution_unit_summary_container_attributes AS a USING(summary_id, container_path);
CREATE VIEW rust_unit_summary_placements AS
 SELECT p.summary_id, a.module_path, p.member_ordinal, a.source_kind,
        p.scope_ordinal, a.enum_scope_node_key,
        CASE c.parent_container_path WHEN '' THEN 'crate' ELSE c.parent_container_path END AS parent_module_path
 FROM resolution_unit_summary_placements AS p
 JOIN rust_resolution_unit_summary_placement_attributes AS a USING(summary_id, container_path, member_ordinal)
 JOIN resolution_unit_summary_containers AS c USING(summary_id, container_path);
CREATE VIEW rust_unit_summary_dependency_names AS
 SELECT summary_id, dependency_ordinal, name AS extern_name, role AS dependency_kind
 FROM resolution_unit_summary_dependency_names;

-- Version 14 republishes Rust summaries with shared placements. Rust route
-- companions retain their native spelling and now reference the attributes'
-- generated native key. Go and JVM summary/version rows are untouched.
-- The upgrader disables foreign-key actions while applying historical DDL.
-- Clear children explicitly, before their headers, so both upgrade modes retire
-- the old Rust derivation without leaving dangling shared membership/version rows.
DELETE FROM rust_resolution_unit_summary_placement_attributes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_placements WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_container_attributes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_containers WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_exports WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_imports WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_dependency_names WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_exports WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_glob_imports WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_glob_reexport_routes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_import_routes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_reexport_routes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_trait_endpoints WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_dependencies WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_dependency_names WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_gaps WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_binding_completeness WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_effective_bindings WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_file_naming WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_generated_names WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_import_route_provenance WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_macro_decisions WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_root_routes WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_placements WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_members WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_reads WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_versions WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summary_versions WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_containers WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_contexts WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM rust_resolution_unit_summary_gaps WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust');
DELETE FROM resolution_unit_summaries WHERE lang='rust';
DROP TABLE rust_resolution_unit_summary_exports;
DROP TABLE rust_resolution_unit_summary_generated_names;
DROP TABLE rust_resolution_unit_summary_glob_imports;
DROP TABLE rust_resolution_unit_summary_glob_reexport_routes;
DROP TABLE rust_resolution_unit_summary_import_routes;
DROP TABLE rust_resolution_unit_summary_reexport_routes;
DROP TABLE rust_resolution_unit_summary_root_routes;
DROP TABLE rust_resolution_unit_summary_trait_endpoints;
DROP TABLE rust_resolution_unit_summary_dependency_names;
DROP TABLE rust_resolution_unit_summary_placements;
DROP TABLE rust_resolution_unit_summary_containers;
CREATE TABLE rust_resolution_unit_summary_exports (
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
  PRIMARY KEY(summary_id, module_path, namespace, name),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, declaration_member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
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
CREATE TABLE rust_resolution_unit_summary_generated_names (
  summary_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  invocation_occurrence_id INTEGER NOT NULL CHECK(invocation_occurrence_id >= 0),
  declaration_id INTEGER NOT NULL CHECK(declaration_id >= 0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type', 'value')),
  name TEXT NOT NULL CHECK(length(name) > 0),
  visibility TEXT NOT NULL CHECK(visibility IN ('public', 'crate', 'restricted', 'private')),
  restricted_module_path TEXT,
  module_item INTEGER NOT NULL CHECK(module_item IN (0, 1)),
  CHECK((visibility = 'restricted') = (restricted_module_path IS NOT NULL)),
  CHECK(module_item = 0 OR namespace = 'type'),
  PRIMARY KEY(summary_id, module_path, namespace, name, member_ordinal,
              invocation_occurrence_id, declaration_id),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_generated_names_declaration
  ON rust_resolution_unit_summary_generated_names(
    summary_id, member_ordinal, declaration_id, invocation_occurrence_id);
CREATE INDEX rust_resolution_unit_summary_generated_names_module
  ON rust_resolution_unit_summary_generated_names(summary_id, module_path, namespace, name);
CREATE INDEX rust_resolution_unit_summary_generated_names_name
  ON rust_resolution_unit_summary_generated_names(name, namespace, summary_id);
CREATE TABLE rust_resolution_unit_summary_glob_imports (
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
              module_path, binder_scope),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_glob_imports_target
  ON rust_resolution_unit_summary_glob_imports(
    summary_id, dependency_ordinal, target_module_path, module_path);
CREATE INDEX rust_resolution_unit_summary_glob_imports_target_identity
  ON rust_resolution_unit_summary_glob_imports(
    target_unit_key, target_module_path, summary_id, module_path, member_ordinal,
    binder_scope, source_import_id);
CREATE TABLE rust_resolution_unit_summary_glob_reexport_routes (
  summary_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
  target_module_path TEXT NOT NULL,
  visibility TEXT NOT NULL CHECK(visibility IN ('public', 'crate', 'restricted', 'private')),
  restricted_module_path TEXT,
  CHECK((visibility = 'restricted') = (restricted_module_path IS NOT NULL)),
  PRIMARY KEY(summary_id, module_path, target_unit_key, target_module_path),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_glob_reexport_routes_target
  ON rust_resolution_unit_summary_glob_reexport_routes(
    summary_id, dependency_ordinal, target_module_path, module_path);
CREATE INDEX rust_resolution_unit_summary_glob_reexport_routes_target_identity
  ON rust_resolution_unit_summary_glob_reexport_routes(
    target_unit_key, target_module_path, summary_id, module_path);
CREATE TABLE rust_resolution_unit_summary_import_routes (
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
              binder_scope, namespace, bound_name),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
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
CREATE TABLE rust_resolution_unit_summary_reexport_routes (
  summary_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  bound_name TEXT NOT NULL CHECK(length(bound_name) > 0),
  target_unit_key BLOB NOT NULL
    CHECK(typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32),
  dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL CHECK(length(target_name) > 0),
  visibility TEXT NOT NULL CHECK(visibility IN ('public', 'crate', 'restricted', 'private')),
  restricted_module_path TEXT,
  CHECK((visibility = 'restricted') = (restricted_module_path IS NOT NULL)),
  PRIMARY KEY(summary_id, module_path, bound_name, target_unit_key,
              target_module_path, target_name),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_container_attributes(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_reexport_routes_target
  ON rust_resolution_unit_summary_reexport_routes(
    summary_id, dependency_ordinal, target_module_path, target_name, module_path);
CREATE INDEX rust_resolution_unit_summary_reexport_routes_target_identity
  ON rust_resolution_unit_summary_reexport_routes(
    target_unit_key, target_module_path, target_name, summary_id, module_path, bound_name);
CREATE TABLE rust_resolution_unit_summary_root_routes (
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
  UNIQUE(summary_id, member_ordinal, module_path, route_key),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, module_path, member_ordinal)
    REFERENCES rust_resolution_unit_summary_placement_attributes(summary_id, module_path, member_ordinal)
    ON DELETE CASCADE
) STRICT;
CREATE INDEX rust_resolution_unit_summary_root_routes_owner
  ON rust_resolution_unit_summary_root_routes(
    summary_id, member_ordinal, module_path, reference_source_site);
CREATE INDEX rust_resolution_unit_summary_root_routes_target
  ON rust_resolution_unit_summary_root_routes(
    target_unit_key, target_module_path, target_name);
CREATE TABLE rust_resolution_unit_summary_trait_endpoints (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  owner_module_path TEXT NOT NULL,
  source_relation_key INTEGER NOT NULL CHECK(source_relation_key >= 0),
  endpoint_role TEXT NOT NULL CHECK(endpoint_role IN ('subject', 'trait')),
  endpoint_state TEXT NOT NULL CHECK(endpoint_state IN ('resolved', 'unresolved')),
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  impl_declaration_id INTEGER CHECK(
    impl_declaration_id IS NULL OR impl_declaration_id BETWEEN 0 AND 4294967295),
  target_unit_key BLOB CHECK(target_unit_key IS NULL OR
    (typeof(target_unit_key) = 'blob' AND length(target_unit_key) = 32)),
  target_module_path TEXT,
  target_identity_id INTEGER REFERENCES resolution_identities(id),
  local_target_member_ordinal INTEGER CHECK(
    local_target_member_ordinal IS NULL OR local_target_member_ordinal >= 0),
  dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
  unresolved_spelling TEXT CHECK(unresolved_spelling IS NULL OR length(unresolved_spelling) > 0),
  unresolved_reason TEXT CHECK(unresolved_reason IS NULL OR length(unresolved_reason) > 0),
  CHECK((endpoint_state = 'resolved' AND target_unit_key IS NOT NULL
         AND target_module_path IS NOT NULL AND target_identity_id IS NOT NULL
         AND unresolved_spelling IS NULL AND unresolved_reason IS NULL)
     OR (endpoint_state = 'unresolved' AND target_unit_key IS NULL
         AND target_identity_id IS NULL AND unresolved_spelling IS NOT NULL
         AND unresolved_reason IS NOT NULL)),
  PRIMARY KEY(summary_id, member_ordinal, owner_module_path, source_relation_key, endpoint_role),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, owner_module_path, member_ordinal)
    REFERENCES rust_resolution_unit_summary_placement_attributes(summary_id, module_path, member_ordinal)
    ON DELETE CASCADE,
  FOREIGN KEY(summary_id, local_target_member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_impl
  ON rust_resolution_unit_summary_trait_endpoints(
    summary_id, member_ordinal, impl_declaration_id, impl_site);
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_target
  ON rust_resolution_unit_summary_trait_endpoints(
    target_unit_key, target_module_path, target_identity_id, summary_id, endpoint_role)
  WHERE endpoint_state = 'resolved';
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_unresolved
  ON rust_resolution_unit_summary_trait_endpoints(endpoint_role, unresolved_spelling, summary_id)
  WHERE endpoint_state = 'unresolved';
