DROP VIEW rust_unit_summary_placements;
-- #11183 M2: invalidate obsolete summaries and remove dense coordinates.
-- The migration runner supplies the transaction and disables foreign keys.
DELETE FROM python_unit_summary_export_names;
DELETE FROM python_unit_summary_imports;
DELETE FROM python_unit_summary_providers;
DELETE FROM python_unit_summary_roots;
DELETE FROM python_unit_summary_spellings;
DELETE FROM python_unit_summary_surfaces;
DELETE FROM resolution_unit_summary_containers;
DELETE FROM resolution_unit_summary_dependencies;
DELETE FROM resolution_unit_summary_dependency_names;
DELETE FROM resolution_unit_summary_exports;
DELETE FROM resolution_unit_summary_gaps;
DELETE FROM resolution_unit_summary_imports;
DELETE FROM resolution_unit_summary_members;
DELETE FROM resolution_unit_summary_placements;
DELETE FROM resolution_unit_summary_reads;
DELETE FROM resolution_unit_summary_versions;
DELETE FROM rust_resolution_unit_summary_binding_completeness;
DELETE FROM rust_resolution_unit_summary_container_attributes;
DELETE FROM rust_resolution_unit_summary_contexts;
DELETE FROM rust_resolution_unit_summary_effective_bindings;
DELETE FROM rust_resolution_unit_summary_exports;
DELETE FROM rust_resolution_unit_summary_file_naming;
DELETE FROM rust_resolution_unit_summary_gaps;
DELETE FROM rust_resolution_unit_summary_generated_names;
DELETE FROM rust_resolution_unit_summary_glob_imports;
DELETE FROM rust_resolution_unit_summary_glob_reexport_routes;
DELETE FROM rust_resolution_unit_summary_import_route_provenance;
DELETE FROM rust_resolution_unit_summary_import_routes;
DELETE FROM rust_resolution_unit_summary_macro_decisions;
DELETE FROM rust_resolution_unit_summary_placement_attributes;
DELETE FROM rust_resolution_unit_summary_reexport_routes;
DELETE FROM rust_resolution_unit_summary_root_routes;
DELETE FROM rust_resolution_unit_summary_trait_endpoints;
DELETE FROM rust_resolution_unit_summary_versions;
DELETE FROM resolution_unit_summary_input_files;
DELETE FROM rust_resolution_unit_summary_binding_owners;
DELETE FROM rust_resolution_unit_summary_binding_names;
DELETE FROM rust_resolution_unit_summary_binding_alternatives;
DELETE FROM rust_resolution_unit_summary_binding_blockers;
DELETE FROM rust_resolution_unit_summary_inherent_impls;
DELETE FROM rust_resolution_unit_summary_unresolved_inherent_impls;
DELETE FROM rust_resolution_unit_summary_public_surface_gaps;
DELETE FROM rust_resolution_unit_summary_inactive_placements;
DELETE FROM resolution_unit_summaries;

DROP TABLE resolution_unit_summary_exports;
CREATE TABLE resolution_unit_summary_exports (
  summary_id            INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  identity_id           INTEGER NOT NULL REFERENCES resolution_identities(id),
  namespace             TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'callable', 'package', 'macro')),
  visibility            TEXT NOT NULL CHECK(visibility IN ('exported', 'unit')),
  origin                TEXT NOT NULL CHECK(origin IN ('declaration', 'alias', 'reexport', 'dot_import')),
  alias_dependency_ordinal INTEGER NULL,
  alias_identity_id     INTEGER NULL REFERENCES resolution_identities(id),
  declaration_member_ordinal INTEGER CHECK(declaration_member_ordinal >= 0),
  site_surface_ordinal INTEGER CHECK(site_surface_ordinal >= 0),
  declaration_surface_ordinal INTEGER CHECK(declaration_surface_ordinal >= 0),
  target_kind TEXT NOT NULL CHECK(target_kind IN ('own','foreign')),
  export_rank INTEGER NOT NULL CHECK(export_rank >= 0),
  CHECK((target_kind = 'own' AND declaration_member_ordinal IS NOT NULL
         AND site_surface_ordinal IS NOT NULL AND declaration_surface_ordinal IS NOT NULL)
     OR (target_kind = 'foreign' AND declaration_member_ordinal IS NULL
         AND site_surface_ordinal IS NULL AND declaration_surface_ordinal IS NULL
         AND alias_dependency_ordinal IS NOT NULL AND alias_identity_id IS NOT NULL)),
  CHECK((alias_dependency_ordinal IS NULL AND alias_identity_id IS NULL)
      = (origin IN ('declaration', 'dot_import'))),
  CHECK(origin NOT IN ('alias', 'reexport') OR alias_identity_id IS NOT NULL),
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal),
  PRIMARY KEY(summary_id, identity_id, namespace, export_rank)
) WITHOUT ROWID, STRICT;

DROP TABLE resolution_unit_summary_imports;
CREATE TABLE resolution_unit_summary_imports (
  summary_id              INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  import_surface_ordinal INTEGER NOT NULL CHECK(import_surface_ordinal >= 0),
  kind                    TEXT NOT NULL CHECK(kind IN ('named', 'blank', 'dot')),
  dependency_ordinal      INTEGER,
  state                   TEXT NOT NULL CHECK(state IN ('resolved', 'unresolved', 'blank')), site_surface_ordinal INTEGER CHECK(site_surface_ordinal >= 0),
  PRIMARY KEY(summary_id, member_ordinal, import_surface_ordinal),
  CHECK((kind = 'dot') = (site_surface_ordinal IS NULL)),
  CHECK((kind = 'blank') = (state = 'blank')),
  CHECK(state IN ('unresolved', 'blank') OR dependency_ordinal IS NOT NULL),
  FOREIGN KEY(summary_id) REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE resolution_unit_summary_placements;
CREATE TABLE resolution_unit_summary_placements (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_surface_ordinal INTEGER CHECK(scope_surface_ordinal >= 0),
 PRIMARY KEY(summary_id, container_path, member_ordinal),
 FOREIGN KEY(summary_id, container_path) REFERENCES resolution_unit_summary_containers(summary_id, container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id, member_ordinal) REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE resolution_unit_summary_members;
CREATE TABLE resolution_unit_summary_members (
  summary_id      INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  member_ordinal  INTEGER NOT NULL CHECK(member_ordinal >= 0),
  blob_id         INTEGER REFERENCES blobs(id) ON DELETE CASCADE,
  rel_path        TEXT NOT NULL CHECK(length(rel_path) > 0),
  source_role     TEXT NOT NULL CHECK(length(source_role) > 0),
  PRIMARY KEY(summary_id, member_ordinal)
) WITHOUT ROWID, STRICT;

DROP TABLE python_unit_summary_export_names;
CREATE TABLE python_unit_summary_export_names(
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 surface TEXT NOT NULL,
 name TEXT NOT NULL CHECK(length(name)>0),
 slot_surface_ordinal INTEGER CHECK(slot_surface_ordinal >= 0),
 PRIMARY KEY(summary_id,container_path,surface,name),
 FOREIGN KEY(summary_id,container_path,surface) REFERENCES python_unit_summary_surfaces(summary_id,container_path,surface) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE python_unit_summary_imports;
CREATE TABLE python_unit_summary_imports(
 summary_id INTEGER NOT NULL,
 member_ordinal INTEGER NOT NULL,
 importer_container TEXT NOT NULL,
 target_container TEXT NOT NULL,
 module_name TEXT NOT NULL,
 relative_level INTEGER NOT NULL CHECK(relative_level>=0),
 requested_name TEXT NOT NULL,
 bound_name TEXT NOT NULL,
 form TEXT NOT NULL CHECK(form IN ('module','from','star')),
 state TEXT NOT NULL CHECK(state IN ('activation_open','provider_open','relative_context_open')), import_surface_ordinal INTEGER NOT NULL CHECK(import_surface_ordinal >= 0),
 PRIMARY KEY(summary_id,member_ordinal,import_surface_ordinal,importer_container,target_container),
 FOREIGN KEY(summary_id,member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,importer_container) REFERENCES resolution_unit_summary_containers(summary_id,container_path) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,target_container) REFERENCES resolution_unit_summary_containers(summary_id,container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX python_unit_summary_imports_reverse ON python_unit_summary_imports(summary_id,target_container,requested_name,form,member_ordinal,import_surface_ordinal);
CREATE INDEX resolution_unit_summary_exports_surface_lookup
  ON resolution_unit_summary_exports(summary_id, declaration_member_ordinal, site_surface_ordinal);
CREATE INDEX resolution_unit_summary_imports_dependency
  ON resolution_unit_summary_imports(summary_id, dependency_ordinal);
CREATE INDEX resolution_unit_summary_members_blob
  ON resolution_unit_summary_members(blob_id, summary_id);
CREATE INDEX resolution_unit_summary_members_path
  ON resolution_unit_summary_members(rel_path, summary_id);
CREATE INDEX resolution_unit_summary_placements_member
 ON resolution_unit_summary_placements(summary_id, member_ordinal, container_path);
CREATE INDEX resolution_unit_summary_placements_surface_lookup
  ON resolution_unit_summary_placements(summary_id, member_ordinal, scope_surface_ordinal);
DROP INDEX resolution_unit_summary_versions_open;
CREATE UNIQUE INDEX resolution_unit_summary_versions_open
  ON resolution_unit_summary_versions(workspace_id, lang, generation, profile_digest, unit_key)
  WHERE valid_until IS NULL;
