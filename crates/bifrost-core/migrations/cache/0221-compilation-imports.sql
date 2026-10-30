-- Compilation-wide imports are sparse source-owned markers.
CREATE TABLE resolution_compilation_imports (
  blob_id INTEGER NOT NULL,
  import_site INTEGER NOT NULL,
  PRIMARY KEY(blob_id, import_site),
  FOREIGN KEY(blob_id, import_site)
    REFERENCES resolution_root_imports(blob_id, import_site) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_compilation_import_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_compilation_import_count >= 0);
