-- Presence cannot be recovered from empty child rows. Discard publications
-- atomically; existing reconciliation republishes each shard from its decoded payload.
DROP TRIGGER catalog_semantic_rows_delete_callable;
DELETE FROM catalog_runtime_contract_payloads;
DELETE FROM catalog_runtime_behaviors;
DELETE FROM catalog_runtime_exposures;
DELETE FROM catalog_runtime_value_payloads;
DELETE FROM catalog_deferred_yields;
DELETE FROM catalog_conditional_type_refinements;
DELETE FROM catalog_collection_flows;
DELETE FROM catalog_procedure_summaries;
DELETE FROM catalog_generator_rules;
DELETE FROM catalog_declaration_relations;
DELETE FROM catalog_member_aliases;
DELETE FROM catalog_declaration_names;
DELETE FROM catalog_declaration_members;
DELETE FROM catalog_declaration_types;
DELETE FROM catalog_anonymous_callable_identity_anchors;
DELETE FROM catalog_anonymous_callable_signature_shapes;
DELETE FROM catalog_anonymous_callable_identities;
DELETE FROM catalog_callable_value_coverage;
DELETE FROM catalog_callable_value_facts;
DROP TABLE catalog_semantic_rows_indexed_shards;
CREATE TABLE catalog_semantic_rows_indexed_shards(
  shard_key INTEGER PRIMARY KEY,
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  index_version INTEGER NOT NULL CHECK(index_version = 3),
  has_callable_values INTEGER NOT NULL CHECK(has_callable_values IN (0, 1)),
  UNIQUE(manifest_digest, shard_id),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER catalog_semantic_rows_delete_callable AFTER DELETE ON
    catalog_semantic_rows_indexed_shards
BEGIN
 DELETE FROM catalog_callable_value_facts WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
 DELETE FROM catalog_callable_value_coverage WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
 DELETE FROM catalog_anonymous_callable_identities WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
END;


ALTER TABLE catalog_procedure_summaries ADD COLUMN record_id TEXT
  GENERATED ALWAYS AS (json_extract(record_json, '$.id')) VIRTUAL;
CREATE INDEX catalog_procedure_summaries_record_id
  ON catalog_procedure_summaries(shard_key, record_id);
