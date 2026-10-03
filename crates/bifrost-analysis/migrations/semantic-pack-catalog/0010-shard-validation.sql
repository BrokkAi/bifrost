-- Reader: hydrate one exact shard under the current validator and decode limits.
-- The primary key serves that equality lookup; no inventory scan is needed.
-- Existing catalogs have no certificates and must validate on their first read.
CREATE TABLE catalog_shard_validations (
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  validation_version INTEGER NOT NULL CHECK(validation_version > 0),
  limits_sha256 TEXT NOT NULL CHECK(length(limits_sha256) = 64),
  PRIMARY KEY(manifest_digest, shard_id, validation_version, limits_sha256),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Readers: full exact-production lookup and the lightweight publication check.
-- Both require a verified pack and its exact generated source row. The
-- production primary key and source unique key serve these point lookups.
CREATE VIEW catalog_verified_generated_productions AS
SELECT gp.production_digest, gp.input_digest, gp.producer_name,
       gp.producer_version, gp.schema_version, gp.manifest_digest, p.manifest_bytes
FROM catalog_generated_productions AS gp
JOIN catalog_packs AS p ON p.manifest_digest = gp.manifest_digest
JOIN catalog_sources AS source
  ON source.manifest_digest = gp.manifest_digest
 AND source.source_kind = 'generated'
 AND source.source_id = 'production:' || gp.production_digest
WHERE p.state = 'verified';
