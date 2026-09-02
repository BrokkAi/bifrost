CREATE TABLE catalog_pack_extraction_source_entries(
  manifest_digest TEXT NOT NULL
    REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  source_entry TEXT NOT NULL CHECK(length(source_entry) > 0),
  reason TEXT NOT NULL CHECK(length(reason) > 0),
  PRIMARY KEY(manifest_digest, ordinal)
) STRICT;

CREATE INDEX catalog_pack_extraction_source_entries_entry
  ON catalog_pack_extraction_source_entries(manifest_digest, source_entry);
