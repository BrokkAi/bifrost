-- #9195: One ordered AST package context per Scala resolution reference site.
-- Other languages retain zero counts and their preexisting canonical digests.
ALTER TABLE resolution_fragment_interiors
  ADD COLUMN expected_reference_package_context_count INTEGER NOT NULL DEFAULT 0
  CHECK(expected_reference_package_context_count >= 0 AND
        (semantic_language = 'scala' OR expected_reference_package_context_count = 0));

CREATE TABLE resolution_reference_package_contexts (
  blob_id INTEGER NOT NULL,
  reference_site INTEGER NOT NULL CHECK(reference_site BETWEEN 0 AND 4294967295),
  prefixes BLOB NOT NULL CHECK(json_valid(prefixes, 8) AND json_type(prefixes) = 'array'),
  PRIMARY KEY(blob_id, reference_site),
  FOREIGN KEY(blob_id, reference_site)
    REFERENCES resolution_sites(blob_id, site) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
