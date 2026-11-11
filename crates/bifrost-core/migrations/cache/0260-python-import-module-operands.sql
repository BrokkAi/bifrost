CREATE TABLE python_import_module_operands(
  blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  reference_site INTEGER NOT NULL,
  import_site INTEGER NOT NULL,
  prefix_len INTEGER NOT NULL CHECK(prefix_len >= 1),
  PRIMARY KEY(blob_id, reference_site)
) WITHOUT ROWID, STRICT;
