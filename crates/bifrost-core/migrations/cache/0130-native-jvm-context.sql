-- Source-derived JVM context for one exact Java/Kotlin/Scala snapshot.
-- One publication transaction inserts the context and all children. These facts
-- do not certify an effective Maven model, compiler classpath or JDK inventory.
CREATE TABLE jvm_context_revisions (
  context_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang IN ('java', 'kotlin', 'scala')),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  derivation_version INTEGER NOT NULL CHECK(derivation_version > 0),
  UNIQUE(workspace_id, lang, generation, revision, derivation_version),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) STRICT;

CREATE TABLE jvm_projects (
  project_id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL REFERENCES jvm_context_revisions(context_id) ON DELETE CASCADE,
  pom_file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
  directory TEXT NOT NULL,
  group_id TEXT NOT NULL CHECK(length(group_id) > 0),
  artifact_id TEXT NOT NULL CHECK(length(artifact_id) > 0),
  version_state TEXT NOT NULL CHECK(version_state IN ('missing', 'unresolved', 'resolved')),
  version_value TEXT,
  CHECK((version_state = 'resolved') = (version_value IS NOT NULL)),
  UNIQUE(context_id, pom_file_version_id),
  UNIQUE(context_id, project_id)
) STRICT;
CREATE INDEX idx_jvm_projects_coordinates
  ON jvm_projects(context_id, group_id, artifact_id, version_state, version_value, project_id);

CREATE TABLE jvm_source_roots (
  root_id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL,
  project_id INTEGER NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('main', 'test')),
  root_path TEXT NOT NULL CHECK(length(root_path) > 0),
  UNIQUE(project_id, role),
  UNIQUE(context_id, root_id),
  FOREIGN KEY(context_id, project_id)
    REFERENCES jvm_projects(context_id, project_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE jvm_source_root_files (
  context_id INTEGER NOT NULL,
  root_id INTEGER NOT NULL,
  source_file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
  PRIMARY KEY(root_id, source_file_version_id),
  FOREIGN KEY(context_id, root_id)
    REFERENCES jvm_source_roots(context_id, root_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_jvm_source_root_files_source
  ON jvm_source_root_files(context_id, source_file_version_id, root_id);

-- A direct declaration is retained even when a coordinate cannot be expanded.
-- Missing and unresolved values are distinct; defaults are interpreted by the
-- selected reader, not substituted into this source evidence.
CREATE TABLE jvm_direct_dependencies (
  context_id INTEGER NOT NULL,
  project_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  group_id_state TEXT NOT NULL CHECK(group_id_state IN ('missing', 'unresolved', 'resolved')),
  group_id_value TEXT,
  artifact_id_state TEXT NOT NULL CHECK(artifact_id_state IN ('missing', 'unresolved', 'resolved')),
  artifact_id_value TEXT,
  version_state TEXT NOT NULL CHECK(version_state IN ('missing', 'unresolved', 'resolved')),
  version_value TEXT,
  artifact_type_state TEXT NOT NULL CHECK(artifact_type_state IN ('missing', 'unresolved', 'resolved')),
  artifact_type_value TEXT,
  classifier_state TEXT NOT NULL CHECK(classifier_state IN ('missing', 'unresolved', 'resolved')),
  classifier_value TEXT,
  scope_state TEXT NOT NULL CHECK(scope_state IN ('missing', 'unresolved', 'resolved')),
  scope_value TEXT,
  optional_state TEXT NOT NULL CHECK(optional_state IN ('missing', 'unresolved', 'resolved')),
  optional_value TEXT,
  CHECK((group_id_state = 'resolved') = (group_id_value IS NOT NULL)),
  CHECK((artifact_id_state = 'resolved') = (artifact_id_value IS NOT NULL)),
  CHECK((version_state = 'resolved') = (version_value IS NOT NULL)),
  CHECK((artifact_type_state = 'resolved') = (artifact_type_value IS NOT NULL)),
  CHECK((classifier_state = 'resolved') = (classifier_value IS NOT NULL)),
  CHECK((scope_state = 'resolved') = (scope_value IS NOT NULL)),
  CHECK((optional_state = 'resolved') = (optional_value IS NOT NULL)),
  PRIMARY KEY(project_id, ordinal),
  FOREIGN KEY(context_id, project_id)
    REFERENCES jvm_projects(context_id, project_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE jvm_context_gaps (
  gap_id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL REFERENCES jvm_context_revisions(context_id) ON DELETE CASCADE,
  project_id INTEGER,
  input_file_version_id INTEGER REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
  code TEXT NOT NULL CHECK(length(code) > 0),
  evidence TEXT NOT NULL,
  FOREIGN KEY(context_id, project_id)
    REFERENCES jvm_projects(context_id, project_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX idx_jvm_context_gaps_scope
  ON jvm_context_gaps(context_id, project_id, input_file_version_id, code);

-- Every reader below validates exact snapshot membership and input kind.
-- Equal pom labels or file-version IDs in another language are not domains.
CREATE VIEW jvm_selected_configuration_files AS
SELECT c.context_id, f.file_version_id, f.rel_path, f.blob_oid, b.source_bytes
FROM jvm_context_revisions AS c
JOIN workspace_file_versions AS f
  ON f.workspace_id = c.workspace_id AND f.lang = c.lang AND f.generation = c.generation
 AND f.input_kind = 'configuration' AND f.valid_from <= c.revision
 AND (f.valid_until IS NULL OR f.valid_until > c.revision)
LEFT JOIN workspace_input_sources AS b ON b.content_oid = f.blob_oid;

CREATE VIEW jvm_selected_source_files AS
SELECT c.context_id, f.file_version_id, f.rel_path, f.blob_oid
FROM jvm_context_revisions AS c
JOIN workspace_file_versions AS f
  ON f.workspace_id = c.workspace_id AND f.lang = c.lang AND f.generation = c.generation
 AND f.input_kind = 'source' AND f.valid_from <= c.revision
 AND (f.valid_until IS NULL OR f.valid_until > c.revision);

CREATE VIEW jvm_selected_projects AS
SELECT p.*, f.rel_path AS pom_path, f.blob_oid AS pom_content_oid
FROM jvm_projects AS p
JOIN jvm_selected_configuration_files AS f
  ON f.context_id = p.context_id AND f.file_version_id = p.pom_file_version_id;

CREATE VIEW jvm_selected_source_root_files AS
SELECT m.context_id, m.root_id, m.source_file_version_id, f.rel_path, f.blob_oid,
       r.role, r.root_path, p.project_id, p.pom_path, p.pom_content_oid
FROM jvm_source_root_files AS m
JOIN jvm_selected_source_files AS f
  ON f.context_id = m.context_id AND f.file_version_id = m.source_file_version_id
JOIN jvm_source_roots AS r ON r.context_id = m.context_id AND r.root_id = m.root_id
JOIN jvm_selected_projects AS p ON p.context_id = r.context_id AND p.project_id = r.project_id;

CREATE VIEW jvm_selected_context_gaps AS
SELECT g.*
FROM jvm_context_gaps AS g
JOIN jvm_context_revisions AS c ON c.context_id = g.context_id
LEFT JOIN jvm_selected_projects AS p ON p.context_id = g.context_id AND p.project_id = g.project_id
LEFT JOIN workspace_file_versions AS f
  ON f.file_version_id = g.input_file_version_id
 AND f.workspace_id = c.workspace_id AND f.lang = c.lang AND f.generation = c.generation
 AND f.valid_from <= c.revision AND (f.valid_until IS NULL OR f.valid_until > c.revision)
WHERE (g.project_id IS NULL OR p.project_id IS NOT NULL)
  AND (g.input_file_version_id IS NULL OR f.file_version_id IS NOT NULL);
