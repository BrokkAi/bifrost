-- #8870: Java ordinary reference sites carry their execution context.
CREATE TABLE resolution_reference_execution_contexts(
  blob_id               INTEGER NOT NULL,
  site                  INTEGER NOT NULL CHECK(site BETWEEN 0 AND 4294967295),
  disposition           TEXT NOT NULL CHECK(disposition IN ('callable', 'non_executable', 'unknown')),
  procedure_kind        TEXT CHECK(procedure_kind IS NULL OR procedure_kind IN
                          ('function', 'method', 'constructor', 'initializer', 'local_function',
                           'lambda', 'closure', 'accessor', 'operator')),
  initializer_is_static INTEGER CHECK(initializer_is_static IS NULL OR initializer_is_static IN (0, 1)),
  callable_site         INTEGER CHECK(callable_site IS NULL OR callable_site BETWEEN 0 AND 4294967295),
  PRIMARY KEY(blob_id, site),
  CHECK((disposition = 'callable') = (procedure_kind IS NOT NULL)),
  CHECK((IFNULL(procedure_kind, '') = 'initializer') = (initializer_is_static IS NOT NULL)),
  CHECK(callable_site IS NULL OR disposition = 'callable'),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, site) REFERENCES resolution_sites(blob_id, site) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, callable_site) REFERENCES resolution_sites(blob_id, site) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_reference_execution_contexts_callable_site
  ON resolution_reference_execution_contexts(blob_id, callable_site);
ALTER TABLE resolution_fragment_interiors
  ADD COLUMN expected_reference_execution_context_count INTEGER NOT NULL DEFAULT 0
  CHECK(expected_reference_execution_context_count >= 0 AND
        (semantic_language = 'java' OR expected_reference_execution_context_count = 0));
