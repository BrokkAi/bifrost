CREATE TABLE catalog_pack_extraction_accounting(
  manifest_digest TEXT PRIMARY KEY
    REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  reject_count INTEGER NOT NULL CHECK(reject_count >= 0),
  suppressed_reject_count INTEGER NOT NULL CHECK(suppressed_reject_count >= 0),
  error_reject_count INTEGER NOT NULL CHECK(error_reject_count >= 0)
) STRICT;

CREATE TABLE catalog_pack_extraction_gaps(
  manifest_digest TEXT NOT NULL
    REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  declaration TEXT NOT NULL CHECK(length(declaration) > 0),
  reason TEXT NOT NULL CHECK(length(reason) > 0),
  PRIMARY KEY(manifest_digest, ordinal)
) STRICT;

CREATE INDEX catalog_pack_extraction_gaps_declaration
  ON catalog_pack_extraction_gaps(manifest_digest, declaration);
