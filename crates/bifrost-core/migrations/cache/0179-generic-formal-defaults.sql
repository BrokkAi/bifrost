-- Generic defaults are read by owner and written application position.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_generic_formal_default_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_generic_formal_default_count >= 0);
CREATE TABLE resolution_generic_formal_defaults (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  owner_definition INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  default_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, owner_definition, ordinal),
  FOREIGN KEY(blob_id, owner_definition) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, default_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
-- Parent deletion's foreign-key check seeks argument slots through this index.
CREATE INDEX resolution_generic_formal_defaults_slot ON resolution_generic_formal_defaults(blob_id, default_slot);
