-- Construction is independent of the component decomposition relation.
-- A production is read by output slot; only arrays carry a literal length.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_type_production_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_type_production_count >= 0);
CREATE TABLE resolution_type_productions (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  output_slot INTEGER NOT NULL,
  element_slot INTEGER NOT NULL,
  constructor INTEGER NOT NULL CHECK(constructor IN (3,4)),
  length_token TEXT,
  PRIMARY KEY(blob_id, output_slot),
  CHECK((constructor=4) = (length_token IS NOT NULL)),
  FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, element_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
-- Parent deletion checks the element foreign key through this index.
CREATE INDEX resolution_type_productions_element ON resolution_type_productions(blob_id, element_slot);
