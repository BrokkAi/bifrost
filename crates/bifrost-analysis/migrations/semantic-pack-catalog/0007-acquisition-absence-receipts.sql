CREATE TABLE catalog_semantic_state(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch >= 0)
) STRICT;

INSERT INTO catalog_semantic_state(singleton, mutation_epoch) VALUES(1, 0);

CREATE TABLE catalog_acquisition_absence_receipts(
  request_digest TEXT NOT NULL
    CHECK(length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  release_digest TEXT NOT NULL
    CHECK(length(release_digest) = 64 AND release_digest NOT GLOB '*[^0-9a-f]*'),
  release_repository TEXT NOT NULL CHECK(length(release_repository) > 0),
  release_tag TEXT NOT NULL CHECK(length(release_tag) > 0),
  archive_name TEXT NOT NULL CHECK(length(archive_name) > 0),
  archive_digest TEXT NOT NULL
    CHECK(length(archive_digest) = 64 AND archive_digest NOT GLOB '*[^0-9a-f]*'),
  bundle_schema_version INTEGER NOT NULL CHECK(bundle_schema_version > 0),
  bundle_generator_name TEXT NOT NULL CHECK(length(bundle_generator_name) > 0),
  bundle_generator_version TEXT NOT NULL CHECK(length(bundle_generator_version) > 0),
  semantic_schema_version INTEGER NOT NULL CHECK(semantic_schema_version > 0),
  generated_cache_version INTEGER NOT NULL CHECK(generated_cache_version > 0),
  client_epoch INTEGER NOT NULL CHECK(client_epoch > 0),
  catalog_schema_version INTEGER NOT NULL CHECK(catalog_schema_version > 0),
  catalog_mutation_epoch INTEGER NOT NULL CHECK(catalog_mutation_epoch >= 0),
  source_state_digest TEXT NOT NULL
    CHECK(length(source_state_digest) = 64 AND source_state_digest NOT GLOB '*[^0-9a-f]*'),
  source_count INTEGER NOT NULL CHECK(source_count > 0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(request_digest, release_digest)
) STRICT;

CREATE TABLE catalog_acquisition_absence_receipt_sources(
  request_digest TEXT NOT NULL,
  release_digest TEXT NOT NULL,
  manifest_digest TEXT NOT NULL
    CHECK(length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  source_kind TEXT NOT NULL
    CHECK(source_kind IN ('installed', 'generated', 'pre_shipped', 'workspace_produced')),
  source_id TEXT NOT NULL CHECK(length(source_id) > 0),
  PRIMARY KEY(request_digest, release_digest, manifest_digest, source_kind, source_id),
  FOREIGN KEY(request_digest, release_digest)
    REFERENCES catalog_acquisition_absence_receipts(request_digest, release_digest)
    ON DELETE CASCADE
) STRICT;

CREATE TRIGGER catalog_semantic_epoch_packs_insert AFTER INSERT ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_packs_delete AFTER DELETE ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_packs_update AFTER UPDATE OF manifest_digest, semantic_digest, manifest_bytes, schema_version, pack_id, pack_version, producer_name, producer_version, language, ecosystem, bifrost_compatibility, provenance_json, license, completeness, state, installed_at, verified_at ON catalog_packs
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_objects_insert AFTER INSERT ON catalog_objects
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_objects_delete AFTER DELETE ON catalog_objects
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_objects_update AFTER UPDATE ON catalog_objects
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_shards_insert AFTER INSERT ON catalog_pack_shards
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_shards_delete AFTER DELETE ON catalog_pack_shards
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_shards_update AFTER UPDATE ON catalog_pack_shards
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_selectors_insert AFTER INSERT ON catalog_selectors
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_selectors_delete AFTER DELETE ON catalog_selectors
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_selectors_update AFTER UPDATE ON catalog_selectors
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_targets_insert AFTER INSERT ON catalog_selector_targets
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_targets_delete AFTER DELETE ON catalog_selector_targets
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_targets_update AFTER UPDATE ON catalog_selector_targets
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_configurations_insert AFTER INSERT ON catalog_selector_configurations
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_configurations_delete AFTER DELETE ON catalog_selector_configurations
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_configurations_update AFTER UPDATE ON catalog_selector_configurations
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_routing_insert AFTER INSERT ON catalog_routing_keys
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_routing_delete AFTER DELETE ON catalog_routing_keys
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_routing_update AFTER UPDATE ON catalog_routing_keys
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_sources_insert AFTER INSERT ON catalog_sources
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_sources_delete AFTER DELETE ON catalog_sources
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_sources_update AFTER UPDATE ON catalog_sources
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_generated_insert AFTER INSERT ON catalog_generated_productions
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_generated_delete AFTER DELETE ON catalog_generated_productions
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_generated_update AFTER UPDATE ON catalog_generated_productions
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_accounting_insert AFTER INSERT ON catalog_pack_extraction_accounting
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_accounting_delete AFTER DELETE ON catalog_pack_extraction_accounting
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_accounting_update AFTER UPDATE ON catalog_pack_extraction_accounting
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_gaps_insert AFTER INSERT ON catalog_pack_extraction_gaps
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_gaps_delete AFTER DELETE ON catalog_pack_extraction_gaps
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_gaps_update AFTER UPDATE ON catalog_pack_extraction_gaps
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_source_entries_insert AFTER INSERT ON catalog_pack_extraction_source_entries
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_source_entries_delete AFTER DELETE ON catalog_pack_extraction_source_entries
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_source_entries_update AFTER UPDATE ON catalog_pack_extraction_source_entries
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;

CREATE TRIGGER catalog_semantic_epoch_quarantine_insert AFTER INSERT ON catalog_quarantine
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_quarantine_delete AFTER DELETE ON catalog_quarantine
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
CREATE TRIGGER catalog_semantic_epoch_quarantine_update AFTER UPDATE ON catalog_quarantine
BEGIN UPDATE catalog_semantic_state SET mutation_epoch = mutation_epoch + 1 WHERE singleton = 1; END;
