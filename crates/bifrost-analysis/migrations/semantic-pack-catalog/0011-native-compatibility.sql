-- The caller disables foreign-key enforcement before opening the transaction.
-- Rebuilding this parent table while it is enabled would run ON DELETE
-- CASCADE for every catalog child row.
CREATE TABLE catalog_packs_v11(
  manifest_digest TEXT PRIMARY KEY
    CHECK(length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  semantic_digest TEXT NOT NULL
    CHECK(length(semantic_digest) = 64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_bytes BLOB NOT NULL,
  schema_version INTEGER NOT NULL,
  pack_id TEXT NOT NULL,
  pack_version TEXT NOT NULL,
  producer_name TEXT NOT NULL,
  producer_version TEXT NOT NULL,
  language TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  bifrost_compatibility TEXT,
  provenance_json BLOB NOT NULL,
  license TEXT NOT NULL,
  completeness TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('verified', 'quarantined')),
  installed_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  last_used_at INTEGER,
  CHECK(
    (schema_version BETWEEN 2 AND 7 AND bifrost_compatibility IS NOT NULL)
    OR (schema_version = 8 AND bifrost_compatibility IS NULL)
  )
) STRICT;

INSERT INTO catalog_packs_v11(
  manifest_digest, semantic_digest, manifest_bytes, schema_version,
  pack_id, pack_version, producer_name, producer_version, language,
  ecosystem, bifrost_compatibility, provenance_json, license, completeness,
  state, installed_at, verified_at, last_used_at
)
SELECT
  manifest_digest, semantic_digest, manifest_bytes, schema_version,
  pack_id, pack_version, producer_name, producer_version, language,
  ecosystem, bifrost_compatibility, provenance_json, license, completeness,
  state, installed_at, verified_at, last_used_at
FROM catalog_packs;

-- SQLite validates dependent views during the rename. Remove and recreate the
-- catalog view inside this same transaction so the swap is never published
-- with an invalid reference.
DROP VIEW catalog_verified_generated_productions;
DROP TABLE catalog_packs;
ALTER TABLE catalog_packs_v11 RENAME TO catalog_packs;

CREATE INDEX catalog_packs_lookup
  ON catalog_packs(state, language, ecosystem, manifest_digest);
CREATE INDEX catalog_packs_gc
  ON catalog_packs(state, last_used_at, installed_at, manifest_digest);

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

CREATE TRIGGER catalog_semantic_epoch_packs_insert AFTER INSERT ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_packs_delete AFTER DELETE ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_packs_update AFTER UPDATE OF manifest_digest, semantic_digest, manifest_bytes, schema_version, pack_id, pack_version, producer_name, producer_version, language, ecosystem, bifrost_compatibility, provenance_json, license, completeness, state, installed_at, verified_at ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
