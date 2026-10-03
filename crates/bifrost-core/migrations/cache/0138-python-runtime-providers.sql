-- Immutable Python runtime-provider evidence, bound to one existing analyzer
-- workspace revision. The acquisition digest identifies the complete
-- provider input set; it is deliberately separate from each original archive
-- SHA-256 below.

CREATE TABLE python_runtime_acquisitions(
  acquisition_id INTEGER PRIMARY KEY,
  workspace_id   TEXT    NOT NULL,
  lang           TEXT    NOT NULL CHECK(lang = 'python'),
  generation     INTEGER NOT NULL CHECK(generation >= 0),
  revision       INTEGER NOT NULL CHECK(revision > 0),
  evidence_digest BLOB  NOT NULL
    CHECK(typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32),
  UNIQUE(workspace_id, lang, generation, revision, evidence_digest),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
      ON DELETE CASCADE
) STRICT;

CREATE TABLE python_runtime_environments(
  environment_id INTEGER PRIMARY KEY,
  acquisition_id INTEGER NOT NULL,
  -- Keep the configured spelling even when it cannot be made into a safe
  -- relative scope. NULL scope_path rows remain unresolved global frontiers.
  source_scope   TEXT    NOT NULL CHECK(length(source_scope) > 0),
  scope_path     TEXT,
  scope_depth    INTEGER,
  status         TEXT    NOT NULL CHECK(status IN (
    'archive_verified', 'incomplete', 'unresolved', 'conflicting', 'cancelled'
  )),
  diagnostic     TEXT,
  CHECK((scope_path IS NULL) = (scope_depth IS NULL)),
  CHECK(scope_path IS NOT NULL OR status IN ('unresolved', 'incomplete')),
  CHECK(scope_path IS NULL OR (
    length(scope_path) > 0 AND
    ((scope_path = '.' AND scope_depth = 0) OR
     (scope_path <> '.' AND scope_depth > 0 AND
      substr(scope_path, 1, 1) <> '/' AND
      substr(scope_path, -1, 1) <> '/' AND
      instr(scope_path, '//') = 0 AND
      instr(scope_path, char(92)) = 0 AND
      substr(scope_path, 1, 2) NOT GLOB '[A-Za-z]:' AND
      instr('/' || scope_path || '/', '/./') = 0 AND
      instr('/' || scope_path || '/', '/../') = 0 AND
      scope_depth = 1 + length(scope_path) - length(replace(scope_path, '/', ''))))
  )),
  UNIQUE(environment_id, acquisition_id),
  FOREIGN KEY(acquisition_id)
    REFERENCES python_runtime_acquisitions(acquisition_id) ON DELETE CASCADE
) STRICT;

-- Used by exact (acquisition_id, scope_path) ancestor lookups, unresolved
-- scope enumeration, and acquisition cascade reclamation.
CREATE INDEX python_runtime_environments_by_scope
  ON python_runtime_environments(acquisition_id, scope_path, scope_depth, environment_id);

CREATE TABLE python_runtime_artifacts(
  artifact_id    INTEGER PRIMARY KEY,
  environment_id INTEGER NOT NULL,
  acquisition_id INTEGER NOT NULL,
  purl           TEXT,
  raw_version    TEXT,
  -- SHA-256 of the exact source archive bytes, not evidence_digest.
  archive_sha256 TEXT
    CHECK(archive_sha256 IS NULL OR (
      length(archive_sha256) = 64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
  archive_path   TEXT    NOT NULL CHECK(length(archive_path) > 0),
  installed_root TEXT    NOT NULL CHECK(length(installed_root) > 0),
  status         TEXT    NOT NULL CHECK(status IN (
    'archive_verified', 'incomplete', 'unresolved', 'conflicting', 'cancelled'
  )),
  diagnostic     TEXT,
  CHECK(status <> 'archive_verified' OR (
    purl IS NOT NULL AND length(purl) > 0 AND
    raw_version IS NOT NULL AND length(raw_version) > 0 AND
    archive_sha256 IS NOT NULL
  )),
  UNIQUE(artifact_id, environment_id, acquisition_id),
  FOREIGN KEY(environment_id, acquisition_id)
    REFERENCES python_runtime_environments(environment_id, acquisition_id)
      ON DELETE CASCADE
) STRICT;

-- Covers environment-owned artifact reclamation; artifact_id remains the
-- INTEGER PRIMARY KEY used by member and provider ownership foreign keys.
CREATE INDEX python_runtime_artifacts_by_environment
  ON python_runtime_artifacts(environment_id, acquisition_id, artifact_id);

CREATE TABLE python_runtime_artifact_members(
  member_id              INTEGER PRIMARY KEY,
  artifact_id            INTEGER NOT NULL,
  environment_id         INTEGER NOT NULL,
  acquisition_id         INTEGER NOT NULL,
  archive_member_path    TEXT    NOT NULL CHECK(length(archive_member_path) > 0),
  installed_path         TEXT,
  member_sha256          TEXT
    CHECK(member_sha256 IS NULL OR (
      length(member_sha256) = 64 AND member_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
  installed_sha256       TEXT
    CHECK(installed_sha256 IS NULL OR (
      length(installed_sha256) = 64 AND installed_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
  installed_bytes_match  INTEGER CHECK(installed_bytes_match IN (0, 1)),
  member_role            TEXT    NOT NULL CHECK(member_role IN (
    'runtime', 'stub', 'runtime_stub', 'other'
  )),
  status                 TEXT    NOT NULL CHECK(status IN (
    'bytes_matched', 'stub_only', 'missing_installed', 'content_mismatch',
    'unsupported', 'unresolved'
  )),
  diagnostic             TEXT,
  CHECK(installed_bytes_match IS NOT 1 OR (
    member_sha256 IS NOT NULL AND installed_sha256 IS NOT NULL
    AND installed_sha256 IS member_sha256
  )),
  CHECK(status NOT IN ('bytes_matched', 'stub_only', 'missing_installed',
                       'content_mismatch', 'unsupported') OR member_sha256 IS NOT NULL),
  CHECK(status <> 'bytes_matched' OR (
    member_role IN ('runtime', 'runtime_stub') AND
    installed_path IS NOT NULL AND installed_sha256 IS NOT NULL AND
    installed_bytes_match IS 1
  )),
  CHECK(status <> 'stub_only' OR member_role IN ('stub', 'runtime_stub')),
  CHECK(status <> 'missing_installed' OR (
    installed_bytes_match IS 0
  )),
  CHECK(status <> 'content_mismatch' OR (
    installed_path IS NOT NULL AND installed_sha256 IS NOT NULL AND
    installed_bytes_match IS 0
  )),
  UNIQUE(member_id, artifact_id, environment_id, acquisition_id),
  FOREIGN KEY(artifact_id, environment_id, acquisition_id)
    REFERENCES python_runtime_artifacts(artifact_id, environment_id, acquisition_id)
      ON DELETE CASCADE
) STRICT;

-- Used by independent exact archive/installed-file revalidation.
CREATE INDEX python_runtime_artifact_members_by_acquisition_artifact
  ON python_runtime_artifact_members(acquisition_id, artifact_id, member_id);
CREATE INDEX python_runtime_artifact_members_by_artifact
  ON python_runtime_artifact_members(
    artifact_id, environment_id, acquisition_id, member_id
  );

CREATE TABLE python_runtime_import_providers(
  provider_id     INTEGER PRIMARY KEY,
  acquisition_id  INTEGER NOT NULL,
  environment_id  INTEGER NOT NULL,
  artifact_id     INTEGER NOT NULL,
  member_id       INTEGER,
  import_name     TEXT    NOT NULL CHECK(length(import_name) > 0),
  binding_status  TEXT    NOT NULL CHECK(binding_status IN (
    'unresolved', 'conflict'
  )),
  FOREIGN KEY(environment_id, acquisition_id)
    REFERENCES python_runtime_environments(environment_id, acquisition_id)
      ON DELETE CASCADE,
  FOREIGN KEY(artifact_id, environment_id, acquisition_id)
    REFERENCES python_runtime_artifacts(artifact_id, environment_id, acquisition_id)
      ON DELETE CASCADE,
  FOREIGN KEY(member_id, artifact_id, environment_id, acquisition_id)
    REFERENCES python_runtime_artifact_members(
      member_id, artifact_id, environment_id, acquisition_id
    ) ON DELETE CASCADE
) STRICT;

-- Provider lookup is by the exact request (acquisition, selected environment,
-- import name); the second index supports artifact-owned cascading deletion.
CREATE INDEX python_runtime_import_providers_by_import
  ON python_runtime_import_providers(
    acquisition_id, environment_id, import_name, provider_id
  );
CREATE INDEX python_runtime_import_providers_by_artifact
  ON python_runtime_import_providers(
    artifact_id, environment_id, acquisition_id, provider_id
  );
CREATE INDEX python_runtime_import_providers_by_member
  ON python_runtime_import_providers(
    member_id, artifact_id, environment_id, acquisition_id
  );

CREATE TABLE python_runtime_scope_frontiers(
  frontier_id     INTEGER PRIMARY KEY,
  acquisition_id  INTEGER NOT NULL,
  environment_id  INTEGER NOT NULL,
  kind            TEXT    NOT NULL CHECK(kind IN (
    'extra_installed_candidate', 'source_shadow_candidate',
    'competing_runtime_provider', 'namespace_contributor',
    'package_initializer_effects',
    'candidate_path_collision', 'candidate_identity_unknown',
    'missing_installed_candidate', 'symlink_skipped', 'path_unreadable',
    'scan_limit', 'scan_depth_limit', 'import_path_order_unknown',
    'import_hook_semantics_unknown'
  )),
  root_path       TEXT    NOT NULL CHECK(length(root_path) > 0),
  path            TEXT,
  import_name     TEXT,
  message         TEXT    NOT NULL CHECK(length(message) > 0),
  FOREIGN KEY(environment_id, acquisition_id)
    REFERENCES python_runtime_environments(environment_id, acquisition_id)
      ON DELETE CASCADE
) STRICT;

-- Frontier reads use the exact selected scope and optional import equality;
-- the second index supports environment-owned cascade deletion.
CREATE INDEX python_runtime_frontiers_by_scope
  ON python_runtime_scope_frontiers(
    acquisition_id, environment_id, import_name, frontier_id
  );
CREATE INDEX python_runtime_frontiers_by_environment
  ON python_runtime_scope_frontiers(environment_id, acquisition_id, frontier_id);

-- One optional declared import contract per verified runtime environment.
-- The reader selects this row by both (environment_id, acquisition_id),
-- scoped through python_runtime_environments. Project-config evidence is the
-- standard resolver-affecting-config digest for the declared descriptor.
CREATE TABLE python_runtime_declared_environments(
  declared_environment_id INTEGER PRIMARY KEY,
  environment_id          INTEGER NOT NULL,
  acquisition_id          INTEGER NOT NULL,
  producer_version        TEXT    NOT NULL CHECK(length(CAST(producer_version AS BLOB)) BETWEEN 1 AND 1048576),
  resolver_version        TEXT    NOT NULL CHECK(length(CAST(resolver_version AS BLOB)) BETWEEN 1 AND 1048576),
  interpreter_path        TEXT    NOT NULL CHECK(length(CAST(interpreter_path AS BLOB)) BETWEEN 1 AND 1048576),
  interpreter_sha256      TEXT    NOT NULL CHECK(length(interpreter_sha256) = 64 AND interpreter_sha256 NOT GLOB '*[^0-9a-f]*'),
  interpreter_implementation TEXT NOT NULL CHECK(length(CAST(interpreter_implementation AS BLOB)) BETWEEN 1 AND 1048576),
  interpreter_python_version TEXT NOT NULL CHECK(length(CAST(interpreter_python_version AS BLOB)) BETWEEN 1 AND 1048576),
  interpreter_abi         TEXT    NOT NULL CHECK(length(CAST(interpreter_abi AS BLOB)) BETWEEN 1 AND 1048576),
  interpreter_platform    TEXT    NOT NULL CHECK(length(CAST(interpreter_platform AS BLOB)) BETWEEN 1 AND 1048576),
  isolation_mode          TEXT    NOT NULL CHECK(isolation_mode IN ('isolated', 'environment_sensitive')),
  site_startup_mode       TEXT    NOT NULL CHECK(site_startup_mode IN ('disabled', 'enabled')),
  environment_mode        TEXT    NOT NULL CHECK(environment_mode IN ('cleared', 'explicit_inputs', 'ambient')),
  import_path_mode        TEXT    NOT NULL CHECK(import_path_mode IN ('declared_roots_only', 'environment_augmented')),
  finder_mode              TEXT    NOT NULL CHECK(finder_mode IN ('standard_filesystem', 'custom_hooks')),
  editable_installs_mode  TEXT    NOT NULL CHECK(editable_installs_mode IN ('disabled', 'enabled')),
  native_extensions_mode TEXT    NOT NULL CHECK(native_extensions_mode IN ('disabled', 'enabled')),
  entry_mode               TEXT    NOT NULL CHECK(entry_mode IN ('script', 'module', 'command_string')),
  entry_root_slot_id       TEXT    NOT NULL CHECK(length(CAST(entry_root_slot_id AS BLOB)) BETWEEN 1 AND 1048576),
  entry_relative_path      TEXT    NOT NULL CHECK(length(CAST(entry_relative_path AS BLOB)) <= 1048576),
  working_directory_root_slot_id TEXT NOT NULL CHECK(length(CAST(working_directory_root_slot_id AS BLOB)) BETWEEN 1 AND 1048576),
  working_directory        TEXT    NOT NULL CHECK(length(CAST(working_directory AS BLOB)) <= 1048576),
  project_config_algorithm TEXT    NOT NULL CHECK(project_config_algorithm = 'sha-256'),
  project_config_coverage  TEXT    NOT NULL CHECK(project_config_coverage = 'resolver-affecting-config'),
  project_config_canonicalization TEXT NOT NULL CHECK(project_config_canonicalization = 'https://bifrost.brokk.ai/csmi/python/project-config/rfc8785-v1'),
  project_config_digest   TEXT    NOT NULL CHECK(length(project_config_digest) = 64 AND project_config_digest NOT GLOB '*[^0-9a-f]*'),
  FOREIGN KEY(environment_id, acquisition_id)
    REFERENCES python_runtime_environments(environment_id, acquisition_id)
      ON DELETE CASCADE
) STRICT;

-- Used by the declared-environment reader's exact environment/acquisition
-- selection. This is also the uniqueness constraint for the optional row.
CREATE UNIQUE INDEX python_runtime_declared_environments_by_environment
  ON python_runtime_declared_environments(environment_id, acquisition_id);

-- The ordered resolver roots are read by declared_environment_id and ordinal;
-- their primary key provides that lookup and the required ordering.
CREATE TABLE python_runtime_declared_roots(
  declared_environment_id INTEGER NOT NULL,
  ordinal                 INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 249999),
  semantic_id             TEXT    NOT NULL CHECK(length(CAST(semantic_id AS BLOB)) BETWEEN 1 AND 1048576),
  role                    TEXT    NOT NULL CHECK(role IN ('source', 'standard_library', 'installed_distribution')),
  path                    TEXT    NOT NULL CHECK(length(CAST(path AS BLOB)) BETWEEN 1 AND 1048576),
  artifact_index          INTEGER CHECK(artifact_index IS NULL OR artifact_index BETWEEN 0 AND 4294967295),
  PRIMARY KEY(declared_environment_id, ordinal),
  FOREIGN KEY(declared_environment_id)
    REFERENCES python_runtime_declared_environments(declared_environment_id)
      ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Reject duplicate semantic root IDs within one declaration at insertion;
-- root selection itself uses the table's parent/ordinal primary key.
CREATE UNIQUE INDEX python_runtime_declared_roots_by_semantic_id
  ON python_runtime_declared_roots(declared_environment_id, semantic_id);

-- Ordered exact config inputs; the reader selects by parent and orders by
-- ordinal, so the primary key also covers the query.
CREATE TABLE python_runtime_declared_inputs(
  declared_environment_id INTEGER NOT NULL,
  ordinal                 INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 249999),
  input_id                TEXT    NOT NULL CHECK(length(CAST(input_id AS BLOB)) BETWEEN 1 AND 1048576),
  role                    TEXT    NOT NULL CHECK(role IN (
    'resolver_configuration', 'startup_configuration',
    'environment_configuration', 'extras_configuration', 'entry_configuration'
  )),
  path                    TEXT    NOT NULL CHECK(length(CAST(path AS BLOB)) BETWEEN 1 AND 1048576),
  sha256                  TEXT    NOT NULL CHECK(length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY(declared_environment_id, ordinal),
  FOREIGN KEY(declared_environment_id)
    REFERENCES python_runtime_declared_environments(declared_environment_id)
      ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Reject duplicate config-input IDs within one declaration at insertion;
-- config-input selection itself uses the table's parent/ordinal primary key.
CREATE UNIQUE INDEX python_runtime_declared_inputs_by_input_id
  ON python_runtime_declared_inputs(declared_environment_id, input_id);

-- Extras are an ordered list (including their original spellings); the
-- reader selects by parent and orders by ordinal, covered by the primary key.
CREATE TABLE python_runtime_declared_extras(
  declared_environment_id INTEGER NOT NULL,
  ordinal                 INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 249999),
  extra                   TEXT    NOT NULL CHECK(length(CAST(extra AS BLOB)) BETWEEN 1 AND 1048576),
  PRIMARY KEY(declared_environment_id, ordinal),
  FOREIGN KEY(declared_environment_id)
    REFERENCES python_runtime_declared_environments(declared_environment_id)
      ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
