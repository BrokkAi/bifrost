-- #11183 R4-1 1a. Final migration 0500, assigned by the native-engine coordinator.
CREATE TABLE resolution_rust_impl_declarations(
  blob_id INTEGER NOT NULL,
  declaration INTEGER NOT NULL CHECK(declaration >= 0),
  -- NULL means native attachment is unknown (macro replay or an older row).
  -- Every impl has a scope: NULL never means no scope. Readers fail closed.
  enclosing_scope INTEGER CHECK(enclosing_scope IS NULL OR enclosing_scope >= 0),
  PRIMARY KEY(blob_id, declaration),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_rust_impl_declaration_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_rust_impl_declaration_count >= 0);
ALTER TABLE rust_include_edges ADD COLUMN invocation_occurrence_id
  INTEGER CHECK(invocation_occurrence_id IS NULL OR invocation_occurrence_id >= 0);

CREATE TRIGGER resolution_rust_impl_declarations_seal
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN bifrost_seal_validates(NEW.blob_id) AND NEW.publication_state='complete'
 AND NEW.expected_rust_impl_declaration_count <>
     (SELECT COUNT(*) FROM resolution_rust_impl_declarations WHERE blob_id=NEW.blob_id)
BEGIN SELECT RAISE(ABORT, 'Rust impl declaration count mismatch'); END;
