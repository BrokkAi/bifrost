-- Structural queries retain compact per-file node arenas and CSR role rows in
-- memory. Persist the same facts as one packed, versioned cache value so a new
-- analyzer process can hydrate the hot representation without reparsing.
CREATE TABLE structural_facts_snapshots(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  snapshot_version  INTEGER NOT NULL CHECK(snapshot_version > 0),
  payload           BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, snapshot_version),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blob_meta(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
