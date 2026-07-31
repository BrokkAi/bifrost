CREATE TEMP TABLE migrate_catalog_pack_shards AS
  SELECT * FROM catalog_pack_shards;
CREATE TEMP TABLE migrate_catalog_selectors AS
  SELECT * FROM catalog_selectors;
CREATE TEMP TABLE migrate_catalog_selector_targets AS
  SELECT * FROM catalog_selector_targets;
CREATE TEMP TABLE migrate_catalog_selector_configurations AS
  SELECT * FROM catalog_selector_configurations;
CREATE TEMP TABLE migrate_catalog_routing_keys AS
  SELECT * FROM catalog_routing_keys;

DROP TABLE catalog_selector_targets;
DROP TABLE catalog_selector_configurations;
DROP TABLE catalog_routing_keys;
DROP TABLE catalog_selectors;
DROP TABLE catalog_pack_shards;

CREATE TABLE catalog_pack_shards(
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  shard_id TEXT NOT NULL,
  payload_kind TEXT NOT NULL CHECK(payload_kind IN (
    'declaration_facts', 'generator_rules', 'procedure_summaries'
  )),
  stored_digest TEXT NOT NULL REFERENCES catalog_objects(stored_digest),
  content_digest TEXT NOT NULL
    CHECK(length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'),
  semantic_digest TEXT NOT NULL
    CHECK(length(semantic_digest) = 64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  record_count INTEGER NOT NULL CHECK(record_count >= 0),
  descriptor_json BLOB NOT NULL,
  PRIMARY KEY(manifest_digest, ordinal),
  UNIQUE(manifest_digest, shard_id)
) STRICT;

CREATE INDEX catalog_pack_shards_object
  ON catalog_pack_shards(stored_digest, manifest_digest);

CREATE TABLE catalog_selectors(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  selector_ordinal INTEGER NOT NULL CHECK(selector_ordinal >= 0),
  package_name TEXT,
  package_version TEXT,
  module_name TEXT,
  module_version TEXT,
  toolchain_name TEXT,
  toolchain_version TEXT,
  artifact_sha256 TEXT
    CHECK(artifact_sha256 IS NULL OR (
      length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
  selector_json BLOB NOT NULL,
  PRIMARY KEY(manifest_digest, shard_id, selector_ordinal),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_selectors_package
  ON catalog_selectors(package_name, manifest_digest, shard_id);
CREATE INDEX catalog_selectors_module
  ON catalog_selectors(module_name, manifest_digest, shard_id);
CREATE INDEX catalog_selectors_toolchain
  ON catalog_selectors(toolchain_name, manifest_digest, shard_id);
CREATE INDEX catalog_selectors_artifact
  ON catalog_selectors(artifact_sha256, manifest_digest, shard_id);

CREATE TABLE catalog_selector_targets(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  selector_ordinal INTEGER NOT NULL,
  target TEXT NOT NULL,
  PRIMARY KEY(manifest_digest, shard_id, selector_ordinal, target),
  FOREIGN KEY(manifest_digest, shard_id, selector_ordinal)
    REFERENCES catalog_selectors(manifest_digest, shard_id, selector_ordinal) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_selector_targets_lookup
  ON catalog_selector_targets(target, manifest_digest, shard_id);

CREATE TABLE catalog_selector_configurations(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  selector_ordinal INTEGER NOT NULL,
  configuration TEXT NOT NULL,
  PRIMARY KEY(manifest_digest, shard_id, selector_ordinal, configuration),
  FOREIGN KEY(manifest_digest, shard_id, selector_ordinal)
    REFERENCES catalog_selectors(manifest_digest, shard_id, selector_ordinal) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_selector_configurations_lookup
  ON catalog_selector_configurations(configuration, manifest_digest, shard_id);

CREATE TABLE catalog_routing_keys(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  routing_key TEXT NOT NULL,
  PRIMARY KEY(manifest_digest, shard_id, routing_key),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_routing_keys_lookup
  ON catalog_routing_keys(routing_key, manifest_digest, shard_id);

INSERT INTO catalog_pack_shards SELECT * FROM migrate_catalog_pack_shards;
INSERT INTO catalog_selectors SELECT * FROM migrate_catalog_selectors;
INSERT INTO catalog_selector_targets SELECT * FROM migrate_catalog_selector_targets;
INSERT INTO catalog_selector_configurations
  SELECT * FROM migrate_catalog_selector_configurations;
INSERT INTO catalog_routing_keys SELECT * FROM migrate_catalog_routing_keys;

DROP TABLE migrate_catalog_pack_shards;
DROP TABLE migrate_catalog_selectors;
DROP TABLE migrate_catalog_selector_targets;
DROP TABLE migrate_catalog_selector_configurations;
DROP TABLE migrate_catalog_routing_keys;
