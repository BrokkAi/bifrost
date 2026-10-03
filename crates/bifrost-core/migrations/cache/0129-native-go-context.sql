-- Build-selected Go package context for native resolution.
-- Unit: one captured Go source/config revision and explicit discovery profile.
-- All rows are durable; Rust keeps canonical tool output only during ingestion.
CREATE TABLE go_context_selections (
  selection_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'go'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
  derivation_version INTEGER NOT NULL CHECK(derivation_version > 0),
  UNIQUE(workspace_id, lang, generation, revision, profile_digest, derivation_version),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) STRICT;

-- A retry may produce a new immutable publication for the same selection.
-- The digest includes observed input/provider authority and consumed normalized
-- output, including completeness. It is not just the source/config revision.
-- Gaps are a JSONB array of {code, evidence} objects read whole by completion
-- readers; this avoids a statement per diagnostic and contains no references.
CREATE TABLE go_context_publications (
  context_id INTEGER PRIMARY KEY,
  selection_id INTEGER NOT NULL REFERENCES go_context_selections(selection_id) ON DELETE CASCADE,
  publication_digest BLOB NOT NULL CHECK(length(publication_digest) = 32),
  complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
  gaps BLOB NOT NULL CHECK(json_valid(gaps, 8) AND json_type(gaps) = 'array'),
  UNIQUE(selection_id, publication_digest),
  UNIQUE(selection_id, context_id)
) STRICT;

-- CAS the selected context only after input recheck and atomic child insertion.
-- Existing immutable publications remain available to an operation bound to
-- their context_id; operation completion rechecks this head for withdrawal.
CREATE TABLE go_context_heads (
  selection_id INTEGER PRIMARY KEY REFERENCES go_context_selections(selection_id) ON DELETE CASCADE,
  context_id INTEGER NOT NULL,
  FOREIGN KEY(selection_id, context_id)
    REFERENCES go_context_publications(selection_id, context_id) ON DELETE CASCADE
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
  gaps BLOB NOT NULL CHECK(json_valid(gaps, 8) AND json_type(gaps) = 'array'),
  UNIQUE(context_id, tool_import_path),
  UNIQUE(context_id, package_id)
) STRICT;

-- Forward reader: selected package + role -> source file versions.
CREATE TABLE go_package_files (
  package_id INTEGER NOT NULL REFERENCES go_package_instances(package_id) ON DELETE CASCADE,
  file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
  source_role TEXT NOT NULL CHECK(source_role IN ('go', 'cgo', 'ignored', 'test', 'xtest')),
  PRIMARY KEY(package_id, source_role, file_version_id)
) WITHOUT ROWID, STRICT;
-- Inverse reader: source file version + requested role -> package instances;
-- join package_id to filter exact context_id, without duplicating context_id.
CREATE INDEX idx_go_package_files_file_role ON go_package_files(file_version_id, source_role, package_id);

-- Source alias/dot/blank syntax stays in canonical source_imports. This relation
-- maps the source spelling through tool ImportMap to the selected provider.
-- context_id is repeated to enforce same-context importer and target FKs.
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
-- Reverse reader: actual selected provider -> importing packages/spellings.
CREATE INDEX idx_go_package_imports_target ON go_package_imports(target_package_id, importer_package_id, import_role, source_spelling);

-- Both file placement and package member readers require exact selected source
-- membership. Binding context_id does not silently switch to a newer head.
CREATE VIEW go_context_source_files AS
SELECT packages.context_id, packages.package_id, members.source_role,
       versions.file_version_id, versions.rel_path, versions.blob_oid,
       versions.projection_digest
FROM go_package_files AS members
JOIN go_package_instances AS packages USING(package_id)
JOIN go_context_publications AS publications
  ON publications.context_id = packages.context_id
JOIN go_context_selections AS selected
  ON selected.selection_id = publications.selection_id
JOIN workspace_file_versions AS versions USING(file_version_id)
WHERE versions.workspace_id = selected.workspace_id
  AND versions.lang = selected.lang
  AND versions.generation = selected.generation
  AND versions.input_kind = 'source'
  AND versions.valid_from <= selected.revision
  AND (versions.valid_until IS NULL OR selected.revision < versions.valid_until);
