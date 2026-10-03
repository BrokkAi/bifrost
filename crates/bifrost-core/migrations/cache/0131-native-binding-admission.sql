-- Source-owned Go lexical admission survives ordinary and staged selection.
-- Namespace codes use the canonical ResolutionNamespace vocabulary; only a
-- lexical reference may request spelling admission. Definition masks are the
-- effective Type=1, Value=2, Callable=4, Package=8 set of a supported lexical binder.
ALTER TABLE resolution_sites ADD COLUMN go_spelling_namespace INTEGER
  CHECK(go_spelling_namespace IS NULL OR
    (role=0 AND unqualified IS 1 AND site_kind IS NOT NULL
     AND go_spelling_namespace=namespace AND go_spelling_namespace IN (0,1,2,6)));
ALTER TABLE resolution_sites ADD COLUMN go_definition_namespaces INTEGER
  CHECK(go_definition_namespaces IS NULL OR
    (role=1 AND go_definition_namespaces BETWEEN 1 AND 15));

-- Import tokens carry exact source authority so readers do not classify a
-- static/type import from its rendered path. All fields are absent for other
-- semantic identities, including shared lookup names. Readers seek the
-- existing (blob_id, local_key) catalog primary key.
ALTER TABLE resolution_semantic_catalog ADD COLUMN import_source_site INTEGER
  CHECK(import_source_site IS NULL OR import_source_site BETWEEN 0 AND 4294967295);
ALTER TABLE resolution_semantic_catalog ADD COLUMN import_start_byte INTEGER
  CHECK(import_start_byte IS NULL OR import_start_byte>=0);
ALTER TABLE resolution_semantic_catalog ADD COLUMN import_end_byte INTEGER
  CHECK(import_end_byte IS NULL OR import_end_byte>=import_start_byte);
ALTER TABLE resolution_semantic_catalog ADD COLUMN import_route_kind TEXT
  CHECK((import_source_site IS NULL AND import_start_byte IS NULL
         AND import_end_byte IS NULL AND import_route_kind IS NULL)
    OR (import_source_site IS NOT NULL AND import_start_byte IS NOT NULL
        AND import_end_byte IS NOT NULL AND import_route_kind IS NOT NULL
        AND shared_identity IS NULL
        AND import_route_kind IN ('single_type','type_on_demand','single_static','static_on_demand')));
-- Compatible replacement for migration 128. Correlated project validation
-- permits a point context/project lookup without materializing all projects.
DROP VIEW jvm_selected_context_gaps;
CREATE VIEW jvm_selected_context_gaps AS
SELECT g.*
FROM jvm_context_gaps AS g
JOIN jvm_context_revisions AS c ON c.context_id = g.context_id
LEFT JOIN workspace_file_versions AS f
  ON f.file_version_id = g.input_file_version_id
 AND f.workspace_id = c.workspace_id AND f.lang = c.lang AND f.generation = c.generation
 AND f.valid_from <= c.revision AND (f.valid_until IS NULL OR f.valid_until > c.revision)
WHERE (g.project_id IS NULL OR EXISTS (
  SELECT 1 FROM jvm_selected_projects AS p
  WHERE p.context_id = g.context_id AND p.project_id = g.project_id
))
  AND (g.input_file_version_id IS NULL OR f.file_version_id IS NOT NULL);

-- Protected package halves are authorized by source metadata, independently of
-- external root exports. Readers seek reference authority by source semantic,
-- member authority by token/definition, and package candidates by lookup key.
-- Every semantic/node coordinate names this blob's canonical catalog.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_package_reference_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_package_reference_count>=0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_package_member_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_package_member_count>=0);
CREATE TABLE resolution_package_references(
  blob_id INTEGER NOT NULL,
  token_key INTEGER NOT NULL CHECK(token_key>=0),
  domain_key INTEGER NOT NULL CHECK(domain_key>=0),
  reference_key INTEGER NOT NULL CHECK(reference_key>=0),
  source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
  root_scope_key INTEGER NOT NULL CHECK(root_scope_key>=0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type','value','callable','package')),
  lookup_key INTEGER NOT NULL CHECK(lookup_key>=0),
  PRIMARY KEY(blob_id,token_key),
  UNIQUE(blob_id,reference_key,namespace),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id,token_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,domain_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,reference_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,lookup_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,root_scope_key) REFERENCES resolution_node_catalog(blob_id,local_key)
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_package_members(
  blob_id INTEGER NOT NULL,
  token_key INTEGER NOT NULL CHECK(token_key>=0),
  definition_key INTEGER NOT NULL CHECK(definition_key>=0),
  domain_key INTEGER NOT NULL CHECK(domain_key>=0),
  source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
  root_scope_key INTEGER NOT NULL CHECK(root_scope_key>=0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type','value','callable','package')),
  lookup_key INTEGER NOT NULL CHECK(lookup_key>=0),
  PRIMARY KEY(blob_id,token_key,definition_key),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id,token_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,definition_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,domain_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,lookup_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,root_scope_key) REFERENCES resolution_node_catalog(blob_id,local_key)
) WITHOUT ROWID, STRICT;
-- Named package candidate lookup after the shared identity has been translated
-- through resolution_semantic_catalog's (blob_id,shared_identity) key.
CREATE INDEX resolution_package_members_lookup
  ON resolution_package_members(blob_id,lookup_key);
-- Child probes used when a catalog coordinate is deleted or replaced must
-- not scan every package fact in the blob.
CREATE INDEX resolution_package_references_domain ON resolution_package_references(blob_id,domain_key);
CREATE INDEX resolution_package_references_lookup ON resolution_package_references(blob_id,lookup_key);
CREATE INDEX resolution_package_references_scope ON resolution_package_references(blob_id,root_scope_key);
CREATE INDEX resolution_package_members_definition ON resolution_package_members(blob_id,definition_key);
CREATE INDEX resolution_package_members_domain ON resolution_package_members(blob_id,domain_key);
CREATE INDEX resolution_package_members_scope ON resolution_package_members(blob_id,root_scope_key);

-- A package may satisfy only a positioned Go qualifier. Ordinary TypeOrValue
-- spelling requests keep their original admission, including wrong-kind blockers.
ALTER TABLE resolution_sites ADD COLUMN go_package_qualifier INTEGER NOT NULL DEFAULT 0
  CHECK(go_package_qualifier IN (0,1) AND (go_package_qualifier=0 OR
    (role=0 AND unqualified IS 1 AND namespace=6 AND go_spelling_namespace IS 6)));

-- Actual file-local package import definitions. Selected context supplies the
-- canonical default name; source owns the declaration, span and choice point.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_go_package_import_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_go_package_import_count>=0);
CREATE TABLE resolution_go_package_imports(
  blob_id INTEGER NOT NULL,
  definition_key INTEGER NOT NULL CHECK(definition_key>=0),
  source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
  file_scope_key INTEGER NOT NULL CHECK(file_scope_key>=0),
  spelling_choice_key INTEGER NOT NULL CHECK(spelling_choice_key>=0),
  start_byte INTEGER NOT NULL CHECK(start_byte>=0),
  end_byte INTEGER NOT NULL CHECK(end_byte>=start_byte),
  kind TEXT NOT NULL CHECK(kind IN ('named','blank')),
  PRIMARY KEY(blob_id,definition_key),
  UNIQUE(blob_id,source_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id,definition_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,spelling_choice_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,file_scope_key) REFERENCES resolution_node_catalog(blob_id,local_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_go_package_imports_choice ON resolution_go_package_imports(blob_id,spelling_choice_key);
CREATE INDEX resolution_go_package_imports_scope ON resolution_go_package_imports(blob_id,file_scope_key);
