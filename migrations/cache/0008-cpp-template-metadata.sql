CREATE TABLE unit_cpp_template_metadata(
  blob_oid TEXT    NOT NULL,
  lang     TEXT    NOT NULL,
  unit_key INTEGER NOT NULL,
  metadata BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, unit_key),
  FOREIGN KEY(blob_oid, lang, unit_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

ALTER TABLE blob_meta
  ADD COLUMN cpp_template_metadata_count INTEGER NOT NULL DEFAULT 0
    CHECK(cpp_template_metadata_count >= 0);
