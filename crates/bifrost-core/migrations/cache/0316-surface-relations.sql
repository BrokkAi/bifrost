-- Per-file surfaces are separate products, retired with their exact blob facts.
CREATE TABLE surface_sets (
  set_id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  source_facts_version INTEGER NOT NULL CHECK(source_facts_version > 0),
  go_source_version INTEGER,
  producer_epoch TEXT NOT NULL,
  publication_witness INTEGER NOT NULL CHECK(publication_witness > 0),
  list_digest BLOB NOT NULL CHECK(length(list_digest) = 32),
  fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
  UNIQUE(blob_id, list_digest)
) STRICT;

CREATE TABLE surface_ids (
  set_id INTEGER NOT NULL REFERENCES surface_sets(set_id) ON DELETE CASCADE,
  id_space INTEGER NOT NULL CHECK(id_space >= 0),
  dense_id INTEGER NOT NULL CHECK(dense_id >= 0),
  surface_ordinal INTEGER NOT NULL CHECK(surface_ordinal >= 0),
  PRIMARY KEY(set_id, id_space, dense_id),
  UNIQUE(set_id, id_space, surface_ordinal)
) WITHOUT ROWID, STRICT;
