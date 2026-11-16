-- Compatible-additive: the new family cannot be mistaken for old empty facts.
-- admit_cached_selected_content_for_epoch refuses an older-token producer epoch;
-- the fragment interior is then re-derived. migrate_locked refuses a store with
-- a higher user_version. insert_prepared_bundle_tx inserts manifest rows;
-- write_prepared_blob_rows_tx replaces by deleting the blob, cascading through
-- the manifest to the structural rows.
CREATE TABLE resolution_rust_structural_trait_impls (
  blob_id INTEGER NOT NULL,
  relation_key INTEGER NOT NULL CHECK(relation_key >= 0),
  trait_terminal_spelling TEXT NOT NULL CHECK(length(trait_terminal_spelling) > 0),
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  impl_start_byte INTEGER NOT NULL CHECK(impl_start_byte >= 0),
  impl_end_byte INTEGER NOT NULL CHECK(impl_end_byte >= impl_start_byte),
  PRIMARY KEY(blob_id, relation_key),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_rust_structural_trait_impls_spelling
  ON resolution_rust_structural_trait_impls(trait_terminal_spelling, blob_id, relation_key);
ALTER TABLE resolution_fragment_interiors
  ADD COLUMN expected_structural_trait_impl_count INTEGER NOT NULL DEFAULT 0
  CHECK(expected_structural_trait_impl_count >= 0);
