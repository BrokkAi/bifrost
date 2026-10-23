-- Replace revision-bound Go tool contexts with domain publication intervals.
DROP VIEW go_context_source_files;
-- Historical DDL runs with foreign-key actions disabled. Retire shared
-- Go summary children explicitly, before their dependencies and headers.
DELETE FROM resolution_unit_summary_placements WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_exports WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_imports WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_dependency_names WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_dependencies WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_gaps WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_reads WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_members WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_containers WHERE summary_id IN
  (SELECT summary_id FROM resolution_unit_summaries WHERE lang = 'go');
DELETE FROM resolution_unit_summary_versions WHERE lang = 'go';
DELETE FROM resolution_unit_summaries WHERE lang = 'go';
DELETE FROM go_context_selections;
DROP TABLE go_context_heads;
DROP TABLE go_package_files;
DROP TABLE go_package_imports;
DROP TABLE go_package_instances;
DROP TABLE go_context_publications;
DROP TABLE go_context_selections;
CREATE TABLE go_context_selections (
  selection_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'go'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  base_profile_digest BLOB NOT NULL CHECK(length(base_profile_digest) = 32),
  domain_dir TEXT NOT NULL,
  gowork_path TEXT NOT NULL,
  profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
  derivation_version INTEGER NOT NULL CHECK(derivation_version > 0),
  UNIQUE(workspace_id, lang, generation, base_profile_digest, domain_dir, gowork_path, derivation_version)
) STRICT;

CREATE TABLE go_context_publications (
  context_id INTEGER PRIMARY KEY,
  selection_id INTEGER NOT NULL REFERENCES go_context_selections(selection_id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'go'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  valid_from INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until INTEGER CHECK(valid_until IS NULL OR valid_until >= valid_from),
  -- Reconciliation-only validity key; answer paths use the interval, never this digest.
  input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
  publication_digest BLOB NOT NULL CHECK(length(publication_digest) = 32),
  complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
  gaps BLOB NOT NULL CHECK(json_valid(gaps, 8) AND json_type(gaps) = 'array'),
  FOREIGN KEY(workspace_id, lang, generation, valid_from)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) STRICT;

CREATE TABLE go_package_instances (
  package_id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL REFERENCES go_context_publications(context_id) ON DELETE CASCADE,
  tool_import_path TEXT NOT NULL CHECK(length(tool_import_path) > 0),
  package_name TEXT NOT NULL,
  for_test TEXT NOT NULL,
  provider_directory TEXT NOT NULL,
  provider_digest BLOB NOT NULL CHECK(length(provider_digest) = 32),
  complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
  gaps BLOB NOT NULL CHECK(json_valid(gaps, 8) AND json_type(gaps) = 'array'), provider_kind TEXT NOT NULL
  DEFAULT 'workspace' CHECK(provider_kind IN ('workspace', 'standard', 'module')), provider_module_path TEXT, provider_module_version TEXT, provider_provenance TEXT NOT NULL
  DEFAULT 'go_tool' CHECK(provider_provenance IN ('go_tool', 'source_inventory')), unit_key BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32 AND unit_key != zeroblob(32)),
  UNIQUE(context_id, tool_import_path),
  UNIQUE(context_id, package_id)
) STRICT;

CREATE TABLE go_package_imports (
  import_id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL,
  importer_package_id INTEGER NOT NULL,
  source_spelling TEXT NOT NULL CHECK(length(source_spelling) > 0),
  import_role TEXT NOT NULL CHECK(import_role IN ('go', 'test', 'xtest')),
  target_package_id INTEGER,
  complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
  gaps BLOB NOT NULL CHECK(json_valid(gaps, 8) AND json_type(gaps) = 'array'),
  CHECK(complete = 0 OR target_package_id IS NOT NULL),
  UNIQUE(importer_package_id, import_role, source_spelling),
  FOREIGN KEY(context_id, importer_package_id)
    REFERENCES go_package_instances(context_id, package_id) ON DELETE CASCADE,
  FOREIGN KEY(context_id, target_package_id)
    REFERENCES go_package_instances(context_id, package_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE go_package_files (
  package_id INTEGER NOT NULL REFERENCES go_package_instances(package_id) ON DELETE CASCADE,
  source_role TEXT NOT NULL CHECK(source_role IN ('go', 'cgo', 'ignored', 'test', 'xtest')),
  rel_path TEXT NOT NULL,
  PRIMARY KEY(package_id, source_role, rel_path)
) WITHOUT ROWID, STRICT;

CREATE TABLE go_context_domain_modules (
  context_id INTEGER NOT NULL REFERENCES go_context_publications(context_id) ON DELETE CASCADE,
  module_dir TEXT NOT NULL,
  module_path TEXT NOT NULL,
  PRIMARY KEY(context_id, module_dir)
) WITHOUT ROWID, STRICT;

CREATE INDEX go_context_selections_profile ON go_context_selections(profile_digest);
CREATE UNIQUE INDEX go_context_publications_open ON go_context_publications(selection_id) WHERE valid_until IS NULL;
CREATE INDEX go_context_domain_modules_directory ON go_context_domain_modules(module_dir, context_id);
CREATE INDEX idx_go_package_files_file_role ON go_package_files(rel_path, package_id);

CREATE INDEX go_package_instances_for_test
  ON go_package_instances(context_id, for_test);

CREATE INDEX go_package_instances_unit_key
  ON go_package_instances(context_id, unit_key);

CREATE INDEX idx_go_package_imports_target ON go_package_imports(target_package_id, importer_package_id, import_role, source_spelling);

CREATE VIEW go_context_source_files AS
SELECT packages.context_id, packages.package_id, path_members.source_role,
       versions.file_version_id, versions.rel_path, versions.blob_oid,
       versions.projection_digest, versions.valid_from, versions.valid_until,
       publications.valid_from AS publication_valid_from,
       publications.valid_until AS publication_valid_until,
       versions.workspace_id, versions.lang, versions.generation
FROM go_package_instances AS packages
CROSS JOIN go_context_publications AS publications ON publications.context_id = packages.context_id
CROSS JOIN go_package_files AS path_members ON path_members.package_id = packages.package_id
CROSS JOIN workspace_file_versions AS versions
  ON versions.workspace_id = publications.workspace_id
 AND versions.lang = publications.lang AND versions.generation = publications.generation
 AND versions.input_kind = 'source' AND versions.rel_path = path_members.rel_path;

CREATE INDEX go_context_publications_selection_interval ON go_context_publications(selection_id, valid_from, valid_until);
CREATE INDEX go_context_publications_revision ON go_context_publications(workspace_id, lang, generation, valid_from);
