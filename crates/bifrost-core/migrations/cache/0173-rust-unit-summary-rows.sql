-- Rust-only resolution inputs and route facts that are part of a Rust crate
-- summary but are not part of the language-neutral summary surface/digest.
-- Every relation lives with one shared summary version and uses member and
-- dependency ordinals to refer to the shared rows.

CREATE TABLE rust_resolution_unit_summary_versions (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  unit_key BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  valid_from INTEGER NOT NULL CHECK(valid_from > 0),
  summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  manifest_file_version_id INTEGER REFERENCES workspace_file_versions(file_version_id),
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, valid_from),
  FOREIGN KEY(workspace_id, lang, generation, unit_key, valid_from)
    REFERENCES resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, valid_from)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_versions_manifest
  ON rust_resolution_unit_summary_versions(
    workspace_id, generation, manifest_file_version_id, unit_key, summary_id)
  WHERE manifest_file_version_id IS NOT NULL;
CREATE INDEX rust_resolution_unit_summary_versions_topology
  ON rust_resolution_unit_summary_versions(
    topology_id, workspace_id, generation, unit_key, valid_from, summary_id);

CREATE TABLE rust_resolution_unit_summary_contexts (
  summary_id INTEGER PRIMARY KEY
    REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  target_kind TEXT NOT NULL CHECK(target_kind IN
    ('lib', 'bin', 'test', 'example', 'bench', 'build', 'detached')),
  crate_name TEXT NOT NULL CHECK(length(crate_name) > 0),
  edition TEXT NOT NULL CHECK(edition IN ('2015', '2018', '2021', '2024')),
  prelude TEXT NOT NULL CHECK(prelude IN ('std', 'core', 'none')),
  cfg_atoms BLOB NOT NULL
    CHECK(json_valid(cfg_atoms, 8) AND json_type(cfg_atoms) = 'array'),
  inventory_complete INTEGER NOT NULL CHECK(inventory_complete IN (0, 1)),
  development_capable INTEGER NOT NULL CHECK(development_capable IN (0, 1))
) STRICT;
CREATE INDEX rust_resolution_unit_summary_contexts_live
  ON rust_resolution_unit_summary_contexts(summary_id, target_kind);

CREATE TABLE rust_resolution_unit_summary_containers (
  summary_id INTEGER NOT NULL
    REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  module_path TEXT NOT NULL CHECK(module_path = 'crate' OR module_path LIKE 'crate::%'),
  kind TEXT NOT NULL CHECK(kind IN ('module', 'enum')),
  placement TEXT NOT NULL CHECK(placement IN
    ('root', 'mod_declaration', 'path_attribute', 'inline', 'enum_declaration')),
  PRIMARY KEY(summary_id, module_path),
  CHECK((module_path = 'crate') = (placement = 'root')),
  CHECK((kind = 'enum') = (placement = 'enum_declaration'))
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_placements (
  summary_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  source_kind TEXT NOT NULL CHECK(source_kind IN ('declared', 'include')),
  scope_ordinal INTEGER CHECK(scope_ordinal IS NULL OR scope_ordinal >= 0),
  enum_scope_node_key INTEGER
    CHECK(enum_scope_node_key IS NULL OR enum_scope_node_key >= 0),
  parent_module_path TEXT,
  CHECK((scope_ordinal IS NULL) <> (enum_scope_node_key IS NULL)),
  CHECK((module_path = 'crate') = (parent_module_path IS NULL)),
  PRIMARY KEY(summary_id, module_path, member_ordinal),
  FOREIGN KEY(summary_id, module_path)
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_placements_member
  ON rust_resolution_unit_summary_placements(summary_id, member_ordinal, module_path);
CREATE INDEX rust_resolution_unit_summary_placements_parent
  ON rust_resolution_unit_summary_placements(summary_id, parent_module_path, module_path);

CREATE TABLE rust_resolution_unit_summary_file_naming (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  package_components BLOB NOT NULL
    CHECK(json_valid(package_components, 8) AND json_type(package_components) = 'array'),
  root_components BLOB NOT NULL
    CHECK(json_valid(root_components, 8) AND json_type(root_components) = 'array'),
  PRIMARY KEY(summary_id, member_ordinal),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_dependency_names (
  summary_id INTEGER NOT NULL,
  dependency_ordinal INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  extern_name TEXT NOT NULL CHECK(length(extern_name) > 0),
  dependency_kind TEXT NOT NULL CHECK(dependency_kind IN ('normal', 'dev', 'build')),
  PRIMARY KEY(summary_id, extern_name),
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_dependency_names_ordinal
  ON rust_resolution_unit_summary_dependency_names(summary_id, dependency_ordinal, extern_name);
CREATE INDEX rust_resolution_unit_summary_dependency_names_owner_extern
  ON rust_resolution_unit_summary_dependency_names(summary_id, extern_name, dependency_ordinal);
CREATE INDEX rust_resolution_unit_summary_dependency_names_extern
  ON rust_resolution_unit_summary_dependency_names(extern_name, summary_id, dependency_ordinal);

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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, declaration_member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_exports_identity
  ON rust_resolution_unit_summary_exports(summary_id, identity_id, namespace);
CREATE INDEX rust_resolution_unit_summary_exports_declaration
  ON rust_resolution_unit_summary_exports(
    summary_id, declaration_member_ordinal, declaration_site, namespace, module_path)
  WHERE origin = 'declaration';
CREATE INDEX rust_resolution_unit_summary_exports_name
  ON rust_resolution_unit_summary_exports(name, namespace, visibility, summary_id, module_path);
CREATE INDEX rust_resolution_unit_summary_exports_alias_target
  ON rust_resolution_unit_summary_exports(
    target_unit_key, target_module_path, target_name, namespace, alias_identity_id,
    summary_id, module_path, name, identity_id, visibility)
  WHERE origin <> 'declaration';

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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_reexport_routes_target
  ON rust_resolution_unit_summary_reexport_routes(
    summary_id, dependency_ordinal, target_module_path, target_name, module_path);
CREATE INDEX rust_resolution_unit_summary_reexport_routes_target_identity
  ON rust_resolution_unit_summary_reexport_routes(
    target_unit_key, target_module_path, target_name, summary_id, module_path, bound_name);

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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_glob_reexport_routes_target
  ON rust_resolution_unit_summary_glob_reexport_routes(
    summary_id, dependency_ordinal, target_module_path, module_path);
CREATE INDEX rust_resolution_unit_summary_glob_reexport_routes_target_identity
  ON rust_resolution_unit_summary_glob_reexport_routes(
    target_unit_key, target_module_path, summary_id, module_path);

-- The per-member fixed-point binding closure used by Rust's import graph.
-- The target is a stable unit/identity pair; declaration coordinates are
-- always joined from that unit's current live summary.
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
  target_declaration_key INTEGER CHECK(
    target_declaration_key IS NULL OR target_declaration_key >= 0),
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
  CHECK((target_identity_id IS NULL) <> (target_declaration_key IS NULL)),
  CHECK((source_import_id IS NULL) = (source_import_ordinal IS NULL)),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_effective_bindings_member_name
  ON rust_resolution_unit_summary_effective_bindings(
    summary_id, member_ordinal, module_path, name, namespace);
-- Consumer summaries can survive a dependency re-export route change. Seek
-- the selected binding by its symbolic name; route ordinals are summary-local.
CREATE INDEX rust_resolution_unit_summary_effective_bindings_module_name
  ON rust_resolution_unit_summary_effective_bindings(
    summary_id, module_path, name, namespace);
CREATE UNIQUE INDEX rust_resolution_unit_summary_effective_bindings_route
  ON rust_resolution_unit_summary_effective_bindings(summary_id, route_provenance_ordinal);
CREATE INDEX rust_resolution_unit_summary_effective_bindings_target
  ON rust_resolution_unit_summary_effective_bindings(
    target_unit_key, target_module_path, target_name, namespace,
    summary_id, module_path, member_ordinal);
CREATE INDEX rust_resolution_unit_summary_effective_bindings_identity
  ON rust_resolution_unit_summary_effective_bindings(
    target_unit_key, target_identity_id, summary_id, member_ordinal);

-- One edge row per source import route and traversed binding. It points into
-- the target unit's current binding closure so route files remain live joins.
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
  target_declaration_key INTEGER CHECK(
    target_declaration_key IS NULL OR target_declaration_key >= 0),
  target_route_provenance_ordinal INTEGER NOT NULL
    CHECK(target_route_provenance_ordinal >= 0),
  CHECK((target_identity_id IS NULL) <> (target_declaration_key IS NULL)),
  -- One import route can reach the same alias binding through two traversed
  -- bindings of its target: the target module binds one name twice (an explicit
  -- re-export that shadows a glob, both reaching one declaration), so the
  -- route's key cannot be the traversed binding's identity alone.
  PRIMARY KEY(summary_id, member_ordinal, import_ordinal,
              route_provenance_ordinal, hop_ordinal,
              target_unit_key, target_route_provenance_ordinal),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_import_route_provenance_owner
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, member_ordinal, import_id, import_ordinal,
    route_provenance_ordinal, hop_ordinal);
CREATE INDEX rust_resolution_unit_summary_import_route_provenance_target
  ON rust_resolution_unit_summary_import_route_provenance(
    target_unit_key, target_binding_module_path, target_binding_name, namespace,
    summary_id, member_ordinal, import_ordinal);
CREATE INDEX rust_resolution_unit_summary_import_route_provenance_binding
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, route_provenance_ordinal, hop_ordinal, target_unit_key,
    target_route_provenance_ordinal);

-- A complete row proves absence from the member's effective binding closure.
-- Incomplete rows retain the typed topology gap that prevents that proof.
CREATE TABLE rust_resolution_unit_summary_binding_completeness (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
  gap_kind TEXT NOT NULL,
  gap_subject TEXT NOT NULL,
  PRIMARY KEY(summary_id, member_ordinal, gap_kind, gap_subject),
  CHECK((complete = 1 AND gap_kind = 'complete' AND gap_subject = '')
     OR (complete = 0 AND gap_kind <> 'complete' AND length(gap_kind) > 0
         AND length(gap_subject) > 0)),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE UNIQUE INDEX rust_resolution_unit_summary_binding_completeness_complete
  ON rust_resolution_unit_summary_binding_completeness(summary_id, member_ordinal)
  WHERE complete = 1;
CREATE INDEX rust_resolution_unit_summary_binding_completeness_member
  ON rust_resolution_unit_summary_binding_completeness(summary_id, member_ordinal, complete,
                                                        gap_kind, gap_subject);

CREATE TABLE rust_resolution_unit_summary_gaps (
  summary_id INTEGER NOT NULL
    REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  gap_kind TEXT NOT NULL CHECK(length(gap_kind) > 0),
  subject TEXT NOT NULL,
  detail BLOB NOT NULL CHECK(json_valid(detail, 8) AND json_type(detail) = 'object'),
  PRIMARY KEY(summary_id, gap_kind, subject)
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_gaps_subject
  ON rust_resolution_unit_summary_gaps(gap_kind, subject, summary_id);

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
    REFERENCES rust_resolution_unit_summary_containers(summary_id, module_path) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_generated_names_name
  ON rust_resolution_unit_summary_generated_names(name, namespace, summary_id);
CREATE INDEX rust_resolution_unit_summary_generated_names_module
  ON rust_resolution_unit_summary_generated_names(summary_id, module_path, namespace, name);
CREATE INDEX rust_resolution_unit_summary_generated_names_declaration
  ON rust_resolution_unit_summary_generated_names(
    summary_id, member_ordinal, declaration_id, invocation_occurrence_id);

CREATE TABLE rust_resolution_unit_summary_macro_decisions (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  invocation_occurrence_id INTEGER NOT NULL CHECK(invocation_occurrence_id >= 0),
  decoration_cfg TEXT NOT NULL CHECK(length(decoration_cfg) > 0),
  PRIMARY KEY(summary_id, member_ordinal, invocation_occurrence_id),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

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
    REFERENCES rust_resolution_unit_summary_placements(summary_id, module_path, member_ordinal)
    ON DELETE CASCADE,
  FOREIGN KEY(summary_id, local_target_member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_target
  ON rust_resolution_unit_summary_trait_endpoints(
    target_unit_key, target_module_path, target_identity_id, summary_id, endpoint_role)
  WHERE endpoint_state = 'resolved';
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_unresolved
  ON rust_resolution_unit_summary_trait_endpoints(endpoint_role, unresolved_spelling, summary_id)
  WHERE endpoint_state = 'unresolved';

-- Outbound source routes from Rust root references. These are facts owned by
-- the referencing crate summary; the target coordinates are Rust module
-- structure and deliberately do not participate in the shared output digest.
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
    REFERENCES rust_resolution_unit_summary_placements(summary_id, module_path, member_ordinal)
    ON DELETE CASCADE
) STRICT;
CREATE INDEX rust_resolution_unit_summary_root_routes_target
  ON rust_resolution_unit_summary_root_routes(
    target_unit_key, target_module_path, target_name);
CREATE INDEX rust_resolution_unit_summary_root_routes_owner
  ON rust_resolution_unit_summary_root_routes(
    summary_id, member_ordinal, module_path, reference_source_site);
CREATE INDEX rust_resolution_unit_summary_trait_endpoints_impl
  ON rust_resolution_unit_summary_trait_endpoints(
    summary_id, member_ordinal, impl_declaration_id, impl_site);
