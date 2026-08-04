-- Analyzer epochs are repeatable compatibility fingerprints. Generations are
-- monotonic publication identities so A -> B -> A cannot revive rows from the
-- first A epoch.
ALTER TABLE analysis_epochs
  ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;

CREATE TABLE analysis_generation_sequence(
  id               INTEGER PRIMARY KEY CHECK(id = 1),
  next_generation  INTEGER NOT NULL CHECK(next_generation > 0)
) STRICT;
INSERT INTO analysis_generation_sequence(id, next_generation) VALUES(1, 1);

ALTER TABLE blobs
  ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_blobs_lang_generation
  ON blobs(lang, generation, blob_oid);

ALTER TABLE path_symbol_units
  ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
DROP INDEX idx_path_symbol_units_lang_exact_fqn;
DROP INDEX idx_path_symbol_units_lang_normalized_fqn;
CREATE INDEX idx_path_symbol_units_lang_generation_exact_fqn
  ON path_symbol_units(lang, generation, exact_fqn);
CREATE INDEX idx_path_symbol_units_lang_generation_normalized_fqn
  ON path_symbol_units(lang, generation, normalized_fqn);

ALTER TABLE path_symbol_snapshots
  ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
