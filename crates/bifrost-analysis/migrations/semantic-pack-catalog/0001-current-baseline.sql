CREATE TABLE catalog_packs(
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
  bifrost_compatibility TEXT NOT NULL,
  provenance_json BLOB NOT NULL,
  license TEXT NOT NULL,
  completeness TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('verified', 'quarantined')),
  installed_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  last_used_at INTEGER
) STRICT;

CREATE INDEX catalog_packs_lookup
  ON catalog_packs(state, language, ecosystem, manifest_digest);

CREATE TABLE catalog_objects(
  stored_digest TEXT PRIMARY KEY
    CHECK(length(stored_digest) = 64 AND stored_digest NOT GLOB '*[^0-9a-f]*'),
  relative_path TEXT NOT NULL UNIQUE,
  stored_size INTEGER NOT NULL CHECK(stored_size >= 0),
  raw_size INTEGER NOT NULL CHECK(raw_size >= 0),
  encoding TEXT NOT NULL CHECK(encoding IN ('raw', 'deflate')),
  verified_at INTEGER NOT NULL
) STRICT;

CREATE TABLE catalog_pack_shards(
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  shard_id TEXT NOT NULL,
  payload_kind TEXT NOT NULL CHECK(payload_kind IN ('declaration_facts', 'generator_rules')),
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

CREATE TABLE catalog_sources(
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  source_kind TEXT NOT NULL
    CHECK(source_kind IN ('installed', 'generated', 'pre_shipped', 'workspace_produced')),
  source_id TEXT NOT NULL,
  installed_at INTEGER NOT NULL,
  PRIMARY KEY(manifest_digest, source_kind, source_id)
) STRICT;

CREATE TABLE catalog_quarantine(
  id INTEGER PRIMARY KEY,
  manifest_digest TEXT NOT NULL,
  reason TEXT NOT NULL,
  detail TEXT NOT NULL,
  detected_at INTEGER NOT NULL
) STRICT;

CREATE INDEX catalog_quarantine_manifest
  ON catalog_quarantine(manifest_digest, detected_at);
