CREATE TABLE catalog_generated_productions(
  production_digest TEXT PRIMARY KEY
    CHECK(length(production_digest) = 64 AND production_digest NOT GLOB '*[^0-9a-f]*'),
  input_digest TEXT NOT NULL
    CHECK(length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
  producer_name TEXT NOT NULL CHECK(length(producer_name) > 0),
  producer_version TEXT NOT NULL CHECK(length(producer_version) > 0),
  schema_version INTEGER NOT NULL CHECK(schema_version > 0),
  manifest_digest TEXT NOT NULL REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX catalog_generated_productions_identity
  ON catalog_generated_productions(
    input_digest, producer_name, producer_version, schema_version
  );

CREATE INDEX catalog_generated_productions_manifest
  ON catalog_generated_productions(manifest_digest, production_digest);
