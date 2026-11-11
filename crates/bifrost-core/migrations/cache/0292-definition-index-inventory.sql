-- Full-membership seeks for the definition inventory, including lookup-only,
-- metadata-only and child-only units. These subsume the two partial indexes.
DROP INDEX idx_code_units_lang_exact_fqn_declarations;
DROP INDEX idx_code_units_lang_identifier_lookup;
CREATE INDEX idx_code_units_lang_exact_fqn ON code_units(lang, exact_fqn, blob_id)
  WHERE exact_fqn IS NOT NULL;
CREATE INDEX idx_code_units_lang_normalized_fqn ON code_units(lang, normalized_fqn, blob_id);
CREATE INDEX idx_code_units_lang_identifier ON code_units(lang, identifier, blob_id);
CREATE INDEX idx_code_units_lang_short_name ON code_units(lang, short_name, blob_id);

-- The inventory state applies only to source versions; NULL on a configuration
-- version does not mean its definition inventory is unknown.
-- NULL is unknown, including every legacy source version. A new projection gets
-- a new file version and cannot inherit the old projection's known state.
-- blob_pending records that the projection half is complete (package facts
-- cover the file, every anchor resolved) and that the blob half is not yet
-- proven. Only the store's two authorized writers move a row to known, in the
-- transaction that proves the blob complete and its readiness available.
-- names_withdrawn records that a blob delete cascaded away the file version's
-- name rows. It is unknown, readiness never promotes it, and only an in-place
-- refill by the publication owner (same file version id, same revision) writes
-- the rows again and returns the state to known.
ALTER TABLE workspace_file_versions ADD COLUMN definition_inventory_state TEXT
  CHECK(definition_inventory_state IS NULL OR definition_inventory_state IN
    ('known', 'blob_pending', 'package_facts_incomplete', 'unresolved_anchor',
     'names_withdrawn'));
CREATE INDEX idx_workspace_file_definition_inventory_unknown
  ON workspace_file_versions(lang, workspace_id, generation, valid_until, file_version_id)
  WHERE definition_inventory_state IS NOT 'known' AND input_kind = 'source';

-- Final, adapter-normalized anchored names belong to the file projection.
-- The store publication owner replaces these rows atomically with its state.
CREATE TABLE workspace_file_definition_name_rows(
  file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
  blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  unit_key INTEGER NOT NULL,
  exact_fqn TEXT NOT NULL,
  normalized_fqn TEXT NOT NULL,
  PRIMARY KEY(file_version_id, blob_id, unit_key),
  FOREIGN KEY(blob_id, unit_key) REFERENCES code_units(blob_id, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- The foreign key on blob_id cascades from every blob delete; without a leading
-- blob_id index each delete would scan the whole table.
CREATE INDEX idx_workspace_file_definition_names_blob
  ON workspace_file_definition_name_rows(blob_id);
CREATE INDEX idx_workspace_file_definition_names_exact
  ON workspace_file_definition_name_rows(exact_fqn, file_version_id, blob_id);
CREATE INDEX idx_workspace_file_definition_names_normalized
  ON workspace_file_definition_name_rows(normalized_fqn, file_version_id, blob_id);
