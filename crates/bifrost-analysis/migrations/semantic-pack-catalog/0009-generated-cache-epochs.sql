-- The primary production digest includes the cache epoch. This older index
-- omitted it and prevented new epochs from coexisting with cached output.
DROP INDEX catalog_generated_productions_identity;

-- NULL marks a historical epoch that this binary has not verified. Migration
-- backfills the current epoch only when its canonical digest matches.
ALTER TABLE catalog_generated_productions ADD COLUMN generated_cache_version INTEGER
  CHECK(generated_cache_version IS NULL OR generated_cache_version > 0);
