-- Widen exactly two shared CHECKs, preserving the entire summary family.
-- The migration runner supplies the atomic transaction with foreign keys enabled.
-- Descendants must be saved before dropping a parent: ON DELETE CASCADE is live.

CREATE TEMP TABLE saved_0196_resolution_unit_summaries AS SELECT rowid AS saved_rowid, summary_id, lang, unit_kind, unit_key, summary_digest, producer_epoch, derivation_version, complete, member_count, export_count, import_count, output_digest, publication_state FROM resolution_unit_summaries;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_containers AS SELECT summary_id, container_path, parent_container_path FROM resolution_unit_summary_containers;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_dependencies AS SELECT summary_id, dependency_ordinal, dependency_unit_key, consumed_output_digest, boundary, provenance FROM resolution_unit_summary_dependencies;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_dependency_names AS SELECT summary_id, role, name, dependency_ordinal FROM resolution_unit_summary_dependency_names;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_gaps AS SELECT summary_id, gap_kind, subject, detail FROM resolution_unit_summary_gaps;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_members AS SELECT summary_id, member_ordinal, blob_id, rel_path, source_role FROM resolution_unit_summary_members;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_reads AS SELECT summary_id, read_ordinal, kind, key_digest, digest FROM resolution_unit_summary_reads;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_versions AS SELECT workspace_id, lang, generation, unit_key, profile_digest, valid_from, valid_until, summary_id FROM resolution_unit_summary_versions;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_contexts AS SELECT rowid AS saved_rowid, summary_id, target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, development_capable FROM rust_resolution_unit_summary_contexts;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_gaps AS SELECT summary_id, gap_kind, subject, detail FROM rust_resolution_unit_summary_gaps;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_exports AS SELECT summary_id, identity_id, namespace, visibility, origin, alias_dependency_ordinal, alias_identity_id, declaration_blob_id, declaration_site, declaration_key FROM resolution_unit_summary_exports;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_imports AS SELECT summary_id, blob_id, import_id, kind, import_definition_key, dependency_ordinal, state FROM resolution_unit_summary_imports;

CREATE TEMP TABLE saved_0196_resolution_unit_summary_placements AS SELECT summary_id, container_path, member_ordinal, scope_ordinal FROM resolution_unit_summary_placements;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_binding_completeness AS SELECT summary_id, member_ordinal, complete, gap_kind, gap_subject FROM rust_resolution_unit_summary_binding_completeness;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_container_attributes AS SELECT summary_id, container_path, kind FROM rust_resolution_unit_summary_container_attributes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_effective_bindings AS SELECT summary_id, member_ordinal, module_path, binder_scope, name, namespace, visibility_kind, visibility_crate_root, visibility_module_path, target_unit_key, target_identity_id, target_declaration_key, target_module_path, target_name, route_provenance_ordinal, source_import_id, source_import_ordinal FROM rust_resolution_unit_summary_effective_bindings;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_file_naming AS SELECT summary_id, member_ordinal, package_components, root_components FROM rust_resolution_unit_summary_file_naming;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_import_route_provenance AS SELECT summary_id, member_ordinal, import_id, import_ordinal, route_provenance_ordinal, hop_ordinal, target_unit_key, target_binding_module_path, target_binding_name, namespace, target_identity_id, target_declaration_key, target_route_provenance_ordinal FROM rust_resolution_unit_summary_import_route_provenance;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_macro_decisions AS SELECT summary_id, member_ordinal, invocation_occurrence_id, decoration_cfg FROM rust_resolution_unit_summary_macro_decisions;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_versions AS SELECT workspace_id, lang, generation, unit_key, profile_digest, valid_from, summary_id, manifest_file_version_id, topology_id FROM rust_resolution_unit_summary_versions;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_exports AS SELECT rowid AS saved_rowid, summary_id, module_path, namespace, name, identity_id, visibility, restricted_module_path, origin, declaration_member_ordinal, declaration_site, alias_dependency_ordinal, target_unit_key, alias_identity_id, target_module_path, target_name FROM rust_resolution_unit_summary_exports;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_generated_names AS SELECT summary_id, module_path, member_ordinal, invocation_occurrence_id, declaration_id, namespace, name, visibility, restricted_module_path, module_item FROM rust_resolution_unit_summary_generated_names;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_glob_imports AS SELECT summary_id, member_ordinal, source_import_id, route_ordinal, module_path, binder_scope, target_unit_key, dependency_ordinal, target_module_path FROM rust_resolution_unit_summary_glob_imports;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_glob_reexport_routes AS SELECT summary_id, module_path, target_unit_key, dependency_ordinal, target_module_path, visibility, restricted_module_path FROM rust_resolution_unit_summary_glob_reexport_routes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_import_routes AS SELECT summary_id, member_ordinal, import_id, route_ordinal, module_path, binder_scope, namespace, bound_name, target_unit_key, dependency_ordinal, target_module_path, target_name FROM rust_resolution_unit_summary_import_routes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_placement_attributes AS SELECT summary_id, container_path, member_ordinal, placement, source_kind, enum_scope_node_key FROM rust_resolution_unit_summary_placement_attributes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_reexport_routes AS SELECT summary_id, module_path, bound_name, target_unit_key, dependency_ordinal, target_module_path, target_name, visibility, restricted_module_path FROM rust_resolution_unit_summary_reexport_routes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_root_routes AS SELECT rowid AS saved_rowid, root_route_id, summary_id, member_ordinal, module_path, route_key, reference_source_site, target_unit_key, target_module_path, target_name FROM rust_resolution_unit_summary_root_routes;

CREATE TEMP TABLE saved_0196_rust_resolution_unit_summary_trait_endpoints AS SELECT summary_id, member_ordinal, owner_module_path, source_relation_key, endpoint_role, endpoint_state, impl_site, impl_declaration_id, target_unit_key, target_module_path, target_identity_id, local_target_member_ordinal, dependency_ordinal, unresolved_spelling, unresolved_reason FROM rust_resolution_unit_summary_trait_endpoints;

DROP TABLE rust_resolution_unit_summary_trait_endpoints;

DROP TABLE rust_resolution_unit_summary_root_routes;

DROP TABLE rust_resolution_unit_summary_reexport_routes;

DROP TABLE rust_resolution_unit_summary_placement_attributes;

DROP TABLE rust_resolution_unit_summary_import_routes;

DROP TABLE rust_resolution_unit_summary_glob_reexport_routes;

DROP TABLE rust_resolution_unit_summary_glob_imports;

DROP TABLE rust_resolution_unit_summary_generated_names;

DROP TABLE rust_resolution_unit_summary_exports;

DROP TABLE rust_resolution_unit_summary_versions;

DROP TABLE rust_resolution_unit_summary_macro_decisions;

DROP TABLE rust_resolution_unit_summary_import_route_provenance;

DROP TABLE rust_resolution_unit_summary_file_naming;

DROP TABLE rust_resolution_unit_summary_effective_bindings;

DROP TABLE rust_resolution_unit_summary_container_attributes;

DROP TABLE rust_resolution_unit_summary_binding_completeness;

DROP TABLE resolution_unit_summary_placements;

DROP TABLE resolution_unit_summary_imports;

DROP TABLE resolution_unit_summary_exports;

DROP TABLE rust_resolution_unit_summary_gaps;

DROP TABLE rust_resolution_unit_summary_contexts;

DROP TABLE resolution_unit_summary_versions;

DROP TABLE resolution_unit_summary_reads;

DROP TABLE resolution_unit_summary_members;

DROP TABLE resolution_unit_summary_gaps;

DROP TABLE resolution_unit_summary_dependency_names;

DROP TABLE resolution_unit_summary_dependencies;

DROP TABLE resolution_unit_summary_containers;

DROP TABLE resolution_unit_summaries;

CREATE TABLE resolution_unit_summaries (
  summary_id          INTEGER PRIMARY KEY,
  lang                TEXT NOT NULL CHECK(length(lang) > 0),
  unit_kind           TEXT NOT NULL CHECK(unit_kind IN ('go_package', 'rust_crate', 'jvm_source_set', 'python_environment')),
  unit_key            BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  summary_digest      BLOB NOT NULL UNIQUE
    CHECK(typeof(summary_digest) = 'blob' AND length(summary_digest) = 32),
  producer_epoch      TEXT NOT NULL CHECK(length(producer_epoch) > 0),
  derivation_version  INTEGER NOT NULL CHECK(derivation_version > 0),
  complete            INTEGER NOT NULL CHECK(complete IN (0, 1)),
  member_count        INTEGER NOT NULL DEFAULT 0 CHECK(member_count >= 0),
  export_count        INTEGER NOT NULL DEFAULT 0 CHECK(export_count >= 0),
  import_count        INTEGER NOT NULL DEFAULT 0 CHECK(import_count >= 0),
  output_digest       BLOB
    CHECK(output_digest IS NULL OR (typeof(output_digest) = 'blob' AND length(output_digest) = 32)),
  publication_state   TEXT NOT NULL CHECK(publication_state IN ('building', 'complete')),
  CHECK((publication_state = 'complete') = (output_digest IS NOT NULL))
) STRICT;

CREATE TABLE resolution_unit_summary_containers (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 container_path TEXT NOT NULL,
 parent_container_path TEXT,
 PRIMARY KEY(summary_id, container_path),
 CHECK((container_path = '') = (parent_container_path IS NULL))
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_unit_summary_dependencies (
  summary_id             INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  dependency_ordinal     INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  dependency_unit_key    BLOB NOT NULL
    CHECK(typeof(dependency_unit_key) = 'blob' AND length(dependency_unit_key) = 32),
  consumed_output_digest BLOB NOT NULL
    CHECK(typeof(consumed_output_digest) = 'blob' AND length(consumed_output_digest) = 32),
  boundary               TEXT NOT NULL CHECK(boundary IN ('workspace', 'external', 'standard')),
  -- Module path and version of a Go external package, as text; NULL otherwise.
  provenance             TEXT CHECK(provenance IS NULL OR length(provenance) > 0),
  PRIMARY KEY(summary_id, dependency_ordinal),
  UNIQUE(summary_id, dependency_unit_key)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_dependencies_unit
  ON resolution_unit_summary_dependencies(dependency_unit_key, summary_id);

CREATE TABLE resolution_unit_summary_dependency_names (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(length(role) > 0),
 name TEXT NOT NULL CHECK(length(name) > 0),
 dependency_ordinal INTEGER CHECK(dependency_ordinal IS NULL OR dependency_ordinal >= 0),
 PRIMARY KEY(summary_id, role, name)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_dependency_names_name
 ON resolution_unit_summary_dependency_names(name, summary_id, dependency_ordinal);

CREATE INDEX resolution_unit_summary_dependency_names_ordinal
 ON resolution_unit_summary_dependency_names(summary_id, dependency_ordinal, name);

CREATE INDEX resolution_unit_summary_dependency_names_owner_name
 ON resolution_unit_summary_dependency_names(summary_id, name, dependency_ordinal);

CREATE TABLE resolution_unit_summary_gaps (
  summary_id  INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  gap_kind    TEXT NOT NULL CHECK(length(gap_kind) > 0),
  subject     TEXT NOT NULL,
  detail      BLOB NOT NULL CHECK(json_valid(detail, 8)),
  PRIMARY KEY(summary_id, gap_kind, subject)
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_unit_summary_members (
  summary_id      INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  member_ordinal  INTEGER NOT NULL CHECK(member_ordinal >= 0),
  blob_id         INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  rel_path        TEXT NOT NULL CHECK(length(rel_path) > 0),
  source_role     TEXT NOT NULL CHECK(length(source_role) > 0),
  PRIMARY KEY(summary_id, member_ordinal)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_members_blob
  ON resolution_unit_summary_members(blob_id, summary_id);

CREATE TABLE resolution_unit_summary_reads (
  summary_id    INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  read_ordinal  INTEGER NOT NULL CHECK(read_ordinal >= 0),
  kind          TEXT NOT NULL CHECK(kind IN ('epoch', 'derivation', 'context_publication', 'configuration', 'pack')),
  key_digest    BLOB NOT NULL CHECK(typeof(key_digest) = 'blob' AND length(key_digest) = 32),
  digest        BLOB NOT NULL CHECK(typeof(digest) = 'blob' AND length(digest) = 32),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_reads_key
  ON resolution_unit_summary_reads(key_digest, summary_id);

CREATE TABLE resolution_unit_summary_versions (
  workspace_id  TEXT NOT NULL CHECK(length(workspace_id) = 64),
  lang          TEXT NOT NULL CHECK(length(lang) > 0),
  generation    INTEGER NOT NULL CHECK(generation >= 0),
  unit_key      BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  profile_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(typeof(profile_digest) = 'blob' AND length(profile_digest) = 32)
    -- Python, like Go, always supplies its selected environment profile.
    CHECK(lang IN ('go', 'python') OR profile_digest = zeroblob(32)),
  valid_from    INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until   INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  summary_id    INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_versions_open
  ON resolution_unit_summary_versions(workspace_id, lang, generation, profile_digest, unit_key)
  WHERE valid_until IS NULL;

CREATE INDEX resolution_unit_summary_versions_summary
  ON resolution_unit_summary_versions(summary_id);

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

CREATE TABLE resolution_unit_summary_exports (
  summary_id            INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  identity_id           INTEGER NOT NULL REFERENCES resolution_identities(id),
  namespace             TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'callable', 'package', 'macro')),
  visibility            TEXT NOT NULL CHECK(visibility IN ('exported', 'unit')),
  origin                TEXT NOT NULL CHECK(origin IN ('declaration', 'alias', 'reexport', 'dot_import')),
  alias_dependency_ordinal INTEGER NULL,
  alias_identity_id     INTEGER NULL REFERENCES resolution_identities(id),
  declaration_blob_id   INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  declaration_site      INTEGER NOT NULL CHECK(declaration_site BETWEEN 0 AND 4294967295), -- resolution_semantic_sites.source_site
  declaration_key       INTEGER NOT NULL CHECK(declaration_key >= 0),
  CHECK((alias_dependency_ordinal IS NULL AND alias_identity_id IS NULL)
      = (origin IN ('declaration', 'dot_import'))),
  CHECK(origin NOT IN ('alias', 'reexport') OR alias_identity_id IS NOT NULL),
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal),
  PRIMARY KEY(summary_id, identity_id, namespace, declaration_blob_id, declaration_site)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_exports_declaration
  ON resolution_unit_summary_exports(declaration_blob_id, declaration_site);

CREATE TABLE resolution_unit_summary_imports (
  summary_id              INTEGER NOT NULL,
  blob_id                 INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  import_id               INTEGER NOT NULL CHECK(import_id >= 0),
  kind                    TEXT NOT NULL CHECK(kind IN ('named', 'blank', 'dot')),
  import_definition_key   INTEGER CHECK(import_definition_key IS NULL OR import_definition_key >= 0),
  dependency_ordinal      INTEGER,
  state                   TEXT NOT NULL CHECK(state IN ('resolved', 'unresolved', 'blank')),
  PRIMARY KEY(summary_id, blob_id, import_id),
  CHECK((kind = 'dot') = (import_definition_key IS NULL)),
  CHECK((kind = 'blank') = (state = 'blank')),
  CHECK(state IN ('unresolved', 'blank') OR dependency_ordinal IS NOT NULL),
  FOREIGN KEY(summary_id) REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_imports_dependency
  ON resolution_unit_summary_imports(summary_id, dependency_ordinal);

CREATE TABLE resolution_unit_summary_placements (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_ordinal INTEGER CHECK(scope_ordinal IS NULL OR scope_ordinal >= 0),
 PRIMARY KEY(summary_id, container_path, member_ordinal),
 FOREIGN KEY(summary_id, container_path) REFERENCES resolution_unit_summary_containers(summary_id, container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id, member_ordinal) REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_unit_summary_placements_member
 ON resolution_unit_summary_placements(summary_id, member_ordinal, container_path);

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

CREATE TABLE rust_resolution_unit_summary_container_attributes (
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 module_path TEXT GENERATED ALWAYS AS (CASE container_path WHEN '' THEN 'crate' ELSE container_path END) VIRTUAL,
 kind TEXT NOT NULL CHECK(kind IN ('module', 'enum')),
 PRIMARY KEY(summary_id, container_path),
 UNIQUE(summary_id, module_path),
 FOREIGN KEY(summary_id, container_path) REFERENCES resolution_unit_summary_containers(summary_id, container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

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

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_binding
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, route_provenance_ordinal, hop_ordinal, target_unit_key,
    target_route_provenance_ordinal);

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_owner
  ON rust_resolution_unit_summary_import_route_provenance(
    summary_id, member_ordinal, import_id, import_ordinal,
    route_provenance_ordinal, hop_ordinal);

CREATE INDEX rust_resolution_unit_summary_import_route_provenance_target
  ON rust_resolution_unit_summary_import_route_provenance(
    target_unit_key, target_binding_module_path, target_binding_name, namespace,
    summary_id, member_ordinal, import_ordinal);

CREATE TABLE rust_resolution_unit_summary_macro_decisions (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  invocation_occurrence_id INTEGER NOT NULL CHECK(invocation_occurrence_id >= 0),
  decoration_cfg TEXT NOT NULL CHECK(length(decoration_cfg) > 0),
  PRIMARY KEY(summary_id, member_ordinal, invocation_occurrence_id),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_versions (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  unit_key BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  profile_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(typeof(profile_digest) = 'blob' AND profile_digest = zeroblob(32)),
  valid_from INTEGER NOT NULL CHECK(valid_from > 0),
  summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  manifest_file_version_id INTEGER REFERENCES workspace_file_versions(file_version_id),
  topology_id INTEGER NOT NULL REFERENCES rust_crate_topologies(topology_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, valid_from),
  FOREIGN KEY(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
    REFERENCES resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, profile_digest, valid_from)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_resolution_unit_summary_versions_manifest
  ON rust_resolution_unit_summary_versions(
    workspace_id, generation, manifest_file_version_id, unit_key, summary_id)
  WHERE manifest_file_version_id IS NOT NULL;

CREATE INDEX rust_resolution_unit_summary_versions_topology
  ON rust_resolution_unit_summary_versions(
    topology_id, workspace_id, generation, unit_key, valid_from, summary_id);

CREATE TABLE "rust_resolution_unit_summary_exports" (
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

CREATE UNIQUE INDEX rust_summary_alias_export_endpoint ON rust_resolution_unit_summary_exports(summary_id,module_path,namespace,name,target_unit_key,target_module_path,target_name) WHERE origin<>'declaration';

CREATE UNIQUE INDEX rust_summary_decl_export_endpoint ON rust_resolution_unit_summary_exports(summary_id,module_path,namespace,name,declaration_member_ordinal,declaration_site) WHERE origin='declaration';

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

CREATE TABLE "rust_resolution_unit_summary_glob_imports" (
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

CREATE TABLE "rust_resolution_unit_summary_import_routes" (
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

CREATE TABLE "rust_resolution_unit_summary_root_routes" (
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

INSERT INTO resolution_unit_summaries(rowid, summary_id, lang, unit_kind, unit_key, summary_digest, producer_epoch, derivation_version, complete, member_count, export_count, import_count, output_digest, publication_state) SELECT * FROM saved_0196_resolution_unit_summaries;

DROP TABLE saved_0196_resolution_unit_summaries;

INSERT INTO resolution_unit_summary_containers(summary_id, container_path, parent_container_path) SELECT * FROM saved_0196_resolution_unit_summary_containers;

DROP TABLE saved_0196_resolution_unit_summary_containers;

INSERT INTO resolution_unit_summary_dependencies(summary_id, dependency_ordinal, dependency_unit_key, consumed_output_digest, boundary, provenance) SELECT * FROM saved_0196_resolution_unit_summary_dependencies;

DROP TABLE saved_0196_resolution_unit_summary_dependencies;

INSERT INTO resolution_unit_summary_dependency_names(summary_id, role, name, dependency_ordinal) SELECT * FROM saved_0196_resolution_unit_summary_dependency_names;

DROP TABLE saved_0196_resolution_unit_summary_dependency_names;

INSERT INTO resolution_unit_summary_gaps(summary_id, gap_kind, subject, detail) SELECT * FROM saved_0196_resolution_unit_summary_gaps;

DROP TABLE saved_0196_resolution_unit_summary_gaps;

INSERT INTO resolution_unit_summary_members(summary_id, member_ordinal, blob_id, rel_path, source_role) SELECT * FROM saved_0196_resolution_unit_summary_members;

DROP TABLE saved_0196_resolution_unit_summary_members;

INSERT INTO resolution_unit_summary_reads(summary_id, read_ordinal, kind, key_digest, digest) SELECT * FROM saved_0196_resolution_unit_summary_reads;

DROP TABLE saved_0196_resolution_unit_summary_reads;

INSERT INTO resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, profile_digest, valid_from, valid_until, summary_id) SELECT * FROM saved_0196_resolution_unit_summary_versions;

DROP TABLE saved_0196_resolution_unit_summary_versions;

INSERT INTO rust_resolution_unit_summary_contexts(rowid, summary_id, target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, development_capable) SELECT * FROM saved_0196_rust_resolution_unit_summary_contexts;

DROP TABLE saved_0196_rust_resolution_unit_summary_contexts;

INSERT INTO rust_resolution_unit_summary_gaps(summary_id, gap_kind, subject, detail) SELECT * FROM saved_0196_rust_resolution_unit_summary_gaps;

DROP TABLE saved_0196_rust_resolution_unit_summary_gaps;

INSERT INTO resolution_unit_summary_exports(summary_id, identity_id, namespace, visibility, origin, alias_dependency_ordinal, alias_identity_id, declaration_blob_id, declaration_site, declaration_key) SELECT * FROM saved_0196_resolution_unit_summary_exports;

DROP TABLE saved_0196_resolution_unit_summary_exports;

INSERT INTO resolution_unit_summary_imports(summary_id, blob_id, import_id, kind, import_definition_key, dependency_ordinal, state) SELECT * FROM saved_0196_resolution_unit_summary_imports;

DROP TABLE saved_0196_resolution_unit_summary_imports;

INSERT INTO resolution_unit_summary_placements(summary_id, container_path, member_ordinal, scope_ordinal) SELECT * FROM saved_0196_resolution_unit_summary_placements;

DROP TABLE saved_0196_resolution_unit_summary_placements;

INSERT INTO rust_resolution_unit_summary_binding_completeness(summary_id, member_ordinal, complete, gap_kind, gap_subject) SELECT * FROM saved_0196_rust_resolution_unit_summary_binding_completeness;

DROP TABLE saved_0196_rust_resolution_unit_summary_binding_completeness;

INSERT INTO rust_resolution_unit_summary_container_attributes(summary_id, container_path, kind) SELECT * FROM saved_0196_rust_resolution_unit_summary_container_attributes;

DROP TABLE saved_0196_rust_resolution_unit_summary_container_attributes;

INSERT INTO rust_resolution_unit_summary_effective_bindings(summary_id, member_ordinal, module_path, binder_scope, name, namespace, visibility_kind, visibility_crate_root, visibility_module_path, target_unit_key, target_identity_id, target_declaration_key, target_module_path, target_name, route_provenance_ordinal, source_import_id, source_import_ordinal) SELECT * FROM saved_0196_rust_resolution_unit_summary_effective_bindings;

DROP TABLE saved_0196_rust_resolution_unit_summary_effective_bindings;

INSERT INTO rust_resolution_unit_summary_file_naming(summary_id, member_ordinal, package_components, root_components) SELECT * FROM saved_0196_rust_resolution_unit_summary_file_naming;

DROP TABLE saved_0196_rust_resolution_unit_summary_file_naming;

INSERT INTO rust_resolution_unit_summary_import_route_provenance(summary_id, member_ordinal, import_id, import_ordinal, route_provenance_ordinal, hop_ordinal, target_unit_key, target_binding_module_path, target_binding_name, namespace, target_identity_id, target_declaration_key, target_route_provenance_ordinal) SELECT * FROM saved_0196_rust_resolution_unit_summary_import_route_provenance;

DROP TABLE saved_0196_rust_resolution_unit_summary_import_route_provenance;

INSERT INTO rust_resolution_unit_summary_macro_decisions(summary_id, member_ordinal, invocation_occurrence_id, decoration_cfg) SELECT * FROM saved_0196_rust_resolution_unit_summary_macro_decisions;

DROP TABLE saved_0196_rust_resolution_unit_summary_macro_decisions;

INSERT INTO rust_resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, profile_digest, valid_from, summary_id, manifest_file_version_id, topology_id) SELECT * FROM saved_0196_rust_resolution_unit_summary_versions;

DROP TABLE saved_0196_rust_resolution_unit_summary_versions;

INSERT INTO rust_resolution_unit_summary_exports(rowid, summary_id, module_path, namespace, name, identity_id, visibility, restricted_module_path, origin, declaration_member_ordinal, declaration_site, alias_dependency_ordinal, target_unit_key, alias_identity_id, target_module_path, target_name) SELECT * FROM saved_0196_rust_resolution_unit_summary_exports;

DROP TABLE saved_0196_rust_resolution_unit_summary_exports;

INSERT INTO rust_resolution_unit_summary_generated_names(summary_id, module_path, member_ordinal, invocation_occurrence_id, declaration_id, namespace, name, visibility, restricted_module_path, module_item) SELECT * FROM saved_0196_rust_resolution_unit_summary_generated_names;

DROP TABLE saved_0196_rust_resolution_unit_summary_generated_names;

INSERT INTO rust_resolution_unit_summary_glob_imports(summary_id, member_ordinal, source_import_id, route_ordinal, module_path, binder_scope, target_unit_key, dependency_ordinal, target_module_path) SELECT * FROM saved_0196_rust_resolution_unit_summary_glob_imports;

DROP TABLE saved_0196_rust_resolution_unit_summary_glob_imports;

INSERT INTO rust_resolution_unit_summary_glob_reexport_routes(summary_id, module_path, target_unit_key, dependency_ordinal, target_module_path, visibility, restricted_module_path) SELECT * FROM saved_0196_rust_resolution_unit_summary_glob_reexport_routes;

DROP TABLE saved_0196_rust_resolution_unit_summary_glob_reexport_routes;

INSERT INTO rust_resolution_unit_summary_import_routes(summary_id, member_ordinal, import_id, route_ordinal, module_path, binder_scope, namespace, bound_name, target_unit_key, dependency_ordinal, target_module_path, target_name) SELECT * FROM saved_0196_rust_resolution_unit_summary_import_routes;

DROP TABLE saved_0196_rust_resolution_unit_summary_import_routes;

INSERT INTO rust_resolution_unit_summary_placement_attributes(summary_id, container_path, member_ordinal, placement, source_kind, enum_scope_node_key) SELECT * FROM saved_0196_rust_resolution_unit_summary_placement_attributes;

DROP TABLE saved_0196_rust_resolution_unit_summary_placement_attributes;

INSERT INTO rust_resolution_unit_summary_reexport_routes(summary_id, module_path, bound_name, target_unit_key, dependency_ordinal, target_module_path, target_name, visibility, restricted_module_path) SELECT * FROM saved_0196_rust_resolution_unit_summary_reexport_routes;

DROP TABLE saved_0196_rust_resolution_unit_summary_reexport_routes;

INSERT INTO rust_resolution_unit_summary_root_routes(rowid, root_route_id, summary_id, member_ordinal, module_path, route_key, reference_source_site, target_unit_key, target_module_path, target_name) SELECT * FROM saved_0196_rust_resolution_unit_summary_root_routes;

DROP TABLE saved_0196_rust_resolution_unit_summary_root_routes;

INSERT INTO rust_resolution_unit_summary_trait_endpoints(summary_id, member_ordinal, owner_module_path, source_relation_key, endpoint_role, endpoint_state, impl_site, impl_declaration_id, target_unit_key, target_module_path, target_identity_id, local_target_member_ordinal, dependency_ordinal, unresolved_spelling, unresolved_reason) SELECT * FROM saved_0196_rust_resolution_unit_summary_trait_endpoints;

DROP TABLE saved_0196_rust_resolution_unit_summary_trait_endpoints;

-- Dormant Python environment outputs. Only the explicit native validation entry
-- publishes these rows until the first production reader and its cost gate.
CREATE TABLE python_unit_summary_roots(
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 root_slot INTEGER NOT NULL CHECK(root_slot>=0),
 root_path TEXT NOT NULL,
 authority TEXT NOT NULL CHECK(authority IN ('workspace','supplied_analysis','checked_runtime')),
 ordered INTEGER NOT NULL CHECK(ordered IN (0,1)),
 observation TEXT NOT NULL CHECK(observation IN ('runtime','typing')),
 target_digest BLOB NOT NULL CHECK(length(target_digest)=32),
 PRIMARY KEY(summary_id,root_slot)
) WITHOUT ROWID, STRICT;
CREATE TABLE python_unit_summary_providers(
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 module_name TEXT NOT NULL CHECK(length(module_name)>0),
 parent_module TEXT NOT NULL,
 root_slot INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('module','package','namespace','installed','stub','model')),
 state TEXT NOT NULL CHECK(state IN ('selected','alternative','shadowed','open')),
 rel_path TEXT NOT NULL,
 member_ordinal INTEGER,
 provider_digest BLOB NOT NULL CHECK(length(provider_digest)=32),
 PRIMARY KEY(summary_id,container_path),
 FOREIGN KEY(summary_id,container_path) REFERENCES resolution_unit_summary_containers(summary_id,container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,root_slot) REFERENCES python_unit_summary_roots(summary_id,root_slot) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX python_unit_summary_providers_module ON python_unit_summary_providers(summary_id,module_name,state);
CREATE TABLE python_unit_summary_imports(
 summary_id INTEGER NOT NULL,
 member_ordinal INTEGER NOT NULL,
 import_site INTEGER NOT NULL CHECK(import_site>=0),
 importer_container TEXT NOT NULL,
 target_container TEXT NOT NULL,
 module_name TEXT NOT NULL,
 relative_level INTEGER NOT NULL CHECK(relative_level>=0),
 requested_name TEXT NOT NULL,
 bound_name TEXT NOT NULL,
 form TEXT NOT NULL CHECK(form IN ('module','from','star')),
 state TEXT NOT NULL CHECK(state IN ('activation_open','provider_open','relative_context_open')),
 PRIMARY KEY(summary_id,member_ordinal,import_site,importer_container,target_container),
 FOREIGN KEY(summary_id,member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,importer_container) REFERENCES resolution_unit_summary_containers(summary_id,container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,target_container) REFERENCES resolution_unit_summary_containers(summary_id,container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE python_unit_summary_surfaces(
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 surface TEXT NOT NULL CHECK(surface IN ('module','wildcard','curated')),
 policy TEXT NOT NULL CHECK(policy IN ('slots','public_names','curated','unknown','absent')),
 PRIMARY KEY(summary_id,container_path,surface),
 FOREIGN KEY(summary_id,container_path) REFERENCES python_unit_summary_providers(summary_id,container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE python_unit_summary_export_names(
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 surface TEXT NOT NULL,
 name TEXT NOT NULL CHECK(length(name)>0),
 slot_site INTEGER CHECK(slot_site>=0),
 PRIMARY KEY(summary_id,container_path,surface,name),
 FOREIGN KEY(summary_id,container_path,surface) REFERENCES python_unit_summary_surfaces(summary_id,container_path,surface) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
