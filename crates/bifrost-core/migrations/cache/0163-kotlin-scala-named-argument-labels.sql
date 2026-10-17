-- Named-argument labels are positioned reference facts. The Kotlin and Scala
-- producers currently fill these rows; the selected call target determines
-- which parameter declaration a label denotes.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_named_argument_label_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_named_argument_label_count >= 0);

CREATE TABLE resolution_named_argument_labels (
  blob_id       INTEGER NOT NULL,
  call_site     INTEGER NOT NULL CHECK(call_site >= 0),
  reference_site INTEGER NOT NULL CHECK(reference_site >= 0),
  label         TEXT NOT NULL CHECK(length(label) > 0),
  PRIMARY KEY(blob_id, call_site, reference_site),
  UNIQUE(blob_id, reference_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, reference_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
