-- Persist positional type arguments on declared type syntax so generic
-- receivers can substitute callable results through their selected owner.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_declared_type_argument_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_declared_type_argument_count >= 0);

CREATE TABLE resolution_declared_type_arguments (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  owner_slot INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  argument_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, owner_slot, ordinal),
  FOREIGN KEY(blob_id, owner_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, argument_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_declared_type_arguments_argument
  ON resolution_declared_type_arguments(blob_id, argument_slot, owner_slot);
