CREATE TABLE catalog_generated_source_identities(
  source_identity TEXT NOT NULL
    CHECK(length(source_identity) = 64 AND source_identity NOT GLOB '*[^0-9a-f]*'),
  producer_name TEXT NOT NULL CHECK(length(producer_name) > 0),
  producer_version TEXT NOT NULL CHECK(length(producer_version) > 0),
  schema_version INTEGER NOT NULL CHECK(schema_version > 0),
  generated_cache_version INTEGER NOT NULL CHECK(generated_cache_version > 0),
  production_digest TEXT NOT NULL
    REFERENCES catalog_generated_productions(production_digest) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(
    source_identity, producer_name, producer_version, schema_version,
    generated_cache_version
  )
) STRICT;

CREATE INDEX catalog_generated_source_identities_production
  ON catalog_generated_source_identities(production_digest);
