-- Hash-only certificates cannot prove admission under different decode limits.
-- Revalidate exact content and retain one measured successful certificate.
DROP TABLE catalog_shard_validations;
CREATE TABLE catalog_shard_validations (
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  validation_version INTEGER NOT NULL CHECK(validation_version > 0),
  max_text_bytes INTEGER NOT NULL CHECK(max_text_bytes >= 0),
  max_depth INTEGER NOT NULL CHECK(max_depth >= 0),
  PRIMARY KEY(manifest_digest, shard_id, validation_version),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
