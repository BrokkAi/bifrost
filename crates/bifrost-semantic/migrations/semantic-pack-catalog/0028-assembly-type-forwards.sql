-- The caller disables foreign-key enforcement before opening the transaction.
-- Rebuilding this parent table while it is enabled would run ON DELETE
-- CASCADE for every catalog child row.
CREATE TABLE catalog_packs_v28(
  manifest_digest TEXT PRIMARY KEY
    CHECK(length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  semantic_digest TEXT NOT NULL
    CHECK(length(semantic_digest) = 64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_object_digest TEXT NOT NULL REFERENCES catalog_objects(stored_digest),
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
  extraction_kind TEXT,
  extraction_input_kind TEXT CHECK(extraction_input_kind IN ('single', 'source_set')),
  extraction_digest TEXT CHECK(length(extraction_digest) = 64 AND extraction_digest NOT GLOB '*[^0-9a-f]*'),
  CHECK((extraction_kind IS NULL AND extraction_input_kind IS NULL AND extraction_digest IS NULL)
    OR (schema_version >= 19 AND extraction_kind IS NOT NULL AND extraction_input_kind IS NOT NULL AND extraction_digest IS NOT NULL)),
  CHECK(
    (schema_version BETWEEN 2 AND 7 AND bifrost_compatibility IS NOT NULL)
    OR (schema_version BETWEEN 8 AND 20 AND bifrost_compatibility IS NULL)
  )
) STRICT;

INSERT INTO catalog_packs_v28(
  manifest_digest, semantic_digest, manifest_object_digest, schema_version,
  pack_id, pack_version, producer_name, producer_version, language,
  ecosystem, bifrost_compatibility, provenance_json, license, completeness,
  state, installed_at, verified_at, last_used_at, extraction_kind, extraction_input_kind, extraction_digest
)
SELECT
  manifest_digest, semantic_digest, manifest_object_digest, schema_version,
  pack_id, pack_version, producer_name, producer_version, language,
  ecosystem, bifrost_compatibility, provenance_json, license, completeness,
  state, installed_at, verified_at, last_used_at, extraction_kind, extraction_input_kind, extraction_digest
FROM catalog_packs;

-- Recreate the dependent view in the same transaction as the parent-table swap.
DROP VIEW catalog_verified_generated_productions;
DROP TABLE catalog_packs;
ALTER TABLE catalog_packs_v28 RENAME TO catalog_packs;

CREATE INDEX catalog_packs_manifest_object ON catalog_packs(manifest_object_digest);

CREATE INDEX catalog_packs_lookup
  ON catalog_packs(state, language, ecosystem, manifest_digest);
CREATE INDEX catalog_packs_gc
  ON catalog_packs(state, last_used_at, installed_at, manifest_digest);

CREATE VIEW catalog_verified_generated_productions AS
SELECT gp.production_digest, gp.input_digest, gp.producer_name,
       gp.producer_version, gp.schema_version, gp.manifest_digest
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
CREATE TRIGGER catalog_semantic_epoch_packs_update AFTER UPDATE OF manifest_digest, semantic_digest, manifest_object_digest, schema_version, pack_id, pack_version, producer_name, producer_version, language, ecosystem, bifrost_compatibility, provenance_json, license, completeness, state, installed_at, verified_at, extraction_kind, extraction_input_kind, extraction_digest ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

-- Session assembly-forward rows.
-- Widen only; preserve both empty-payload presence and existing publications.
ALTER TABLE catalog_semantic_payload_families RENAME TO catalog_semantic_payload_families_v27;
CREATE TABLE catalog_semantic_payload_families(
 shard_key INTEGER NOT NULL REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE CASCADE,
 family TEXT NOT NULL CHECK(family IN ('callable_values','collection_flows',
 'conditional_type_refinements','deferred_yields','type_forwards')),
 PRIMARY KEY(shard_key,family)
) STRICT;
INSERT INTO catalog_semantic_payload_families SELECT * FROM catalog_semantic_payload_families_v27;
DROP TABLE catalog_semantic_payload_families_v27;

CREATE TABLE catalog_assembly_identities(
 manifest_digest TEXT NOT NULL,
 shard_id TEXT NOT NULL,
 name TEXT NOT NULL,
 version TEXT NOT NULL,
 culture TEXT,
 public_key_token TEXT,
 PRIMARY KEY(manifest_digest,shard_id),
 FOREIGN KEY(manifest_digest,shard_id) REFERENCES catalog_pack_shards(manifest_digest,shard_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX catalog_assembly_identities_name ON catalog_assembly_identities(name,culture,public_key_token,manifest_digest,shard_id);

CREATE TABLE catalog_type_forwards(
 manifest_digest TEXT NOT NULL,
 shard_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 name TEXT NOT NULL,
 namespace TEXT NOT NULL,
 outer_ordinal INTEGER,
 target_name TEXT NOT NULL,
 target_version TEXT NOT NULL,
 target_culture TEXT,
 target_public_key_token TEXT,
 PRIMARY KEY(manifest_digest,shard_id,ordinal),
 FOREIGN KEY(manifest_digest,shard_id) REFERENCES catalog_pack_shards(manifest_digest,shard_id) ON DELETE CASCADE,
 FOREIGN KEY(manifest_digest,shard_id,outer_ordinal) REFERENCES catalog_type_forwards(manifest_digest,shard_id,ordinal) DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX catalog_type_forwards_name ON catalog_type_forwards(name,manifest_digest,shard_id);
CREATE INDEX catalog_type_forwards_namespace ON catalog_type_forwards(namespace,manifest_digest,shard_id);
CREATE INDEX catalog_type_forwards_outer ON catalog_type_forwards(manifest_digest,shard_id,outer_ordinal);
CREATE TRIGGER catalog_semantic_rows_delete_forwards AFTER DELETE ON catalog_semantic_rows_indexed_shards
BEGIN
 DELETE FROM catalog_type_forwards WHERE manifest_digest=OLD.manifest_digest AND shard_id=OLD.shard_id;
 DELETE FROM catalog_assembly_identities WHERE manifest_digest=OLD.manifest_digest AND shard_id=OLD.shard_id;
END;
CREATE TRIGGER catalog_type_forwards_outer_insert BEFORE INSERT ON catalog_type_forwards
WHEN NEW.outer_ordinal = NEW.ordinal
BEGIN SELECT RAISE(ABORT,'a type forward cannot contain itself'); END;
CREATE TRIGGER catalog_type_forwards_outer_update BEFORE UPDATE OF outer_ordinal,ordinal ON catalog_type_forwards
WHEN NEW.outer_ordinal = NEW.ordinal
BEGIN SELECT RAISE(ABORT,'a type forward cannot contain itself'); END;

CREATE TRIGGER catalog_type_forwards_consistent_insert AFTER INSERT ON catalog_type_forwards
BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM catalog_type_forwards p
   WHERE p.manifest_digest=NEW.manifest_digest AND p.shard_id=NEW.shard_id AND p.ordinal=NEW.outer_ordinal
    AND (NEW.namespace != p.namespace
      OR substr(NEW.name,1,length(p.name)+1) != p.name || '.'
      OR NEW.target_name != p.target_name OR NEW.target_version != p.target_version
      OR NEW.target_culture IS NOT p.target_culture OR NEW.target_public_key_token IS NOT p.target_public_key_token))
   THEN RAISE(ABORT,'inconsistent outer type forward') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM catalog_type_forwards c
   WHERE c.manifest_digest=NEW.manifest_digest AND c.shard_id=NEW.shard_id AND c.outer_ordinal=NEW.ordinal
    AND (c.namespace != NEW.namespace
      OR substr(c.name,1,length(NEW.name)+1) != NEW.name || '.'
      OR c.target_name != NEW.target_name OR c.target_version != NEW.target_version
      OR c.target_culture IS NOT NEW.target_culture OR c.target_public_key_token IS NOT NEW.target_public_key_token))
   THEN RAISE(ABORT,'inconsistent nested type forward') END;
END;

CREATE TRIGGER catalog_type_forwards_consistent_update AFTER UPDATE ON catalog_type_forwards
BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM catalog_type_forwards p
   WHERE p.manifest_digest=NEW.manifest_digest AND p.shard_id=NEW.shard_id AND p.ordinal=NEW.outer_ordinal
    AND (NEW.namespace != p.namespace
      OR substr(NEW.name,1,length(p.name)+1) != p.name || '.'
      OR NEW.target_name != p.target_name OR NEW.target_version != p.target_version
      OR NEW.target_culture IS NOT p.target_culture OR NEW.target_public_key_token IS NOT p.target_public_key_token))
   THEN RAISE(ABORT,'inconsistent outer type forward') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM catalog_type_forwards c
   WHERE c.manifest_digest=NEW.manifest_digest AND c.shard_id=NEW.shard_id AND c.outer_ordinal=NEW.ordinal
    AND (c.namespace != NEW.namespace
      OR substr(c.name,1,length(NEW.name)+1) != NEW.name || '.'
      OR c.target_name != NEW.target_name OR c.target_version != NEW.target_version
      OR c.target_culture IS NOT NEW.target_culture OR c.target_public_key_token IS NOT NEW.target_public_key_token))
   THEN RAISE(ABORT,'inconsistent nested type forward') END;
END;
