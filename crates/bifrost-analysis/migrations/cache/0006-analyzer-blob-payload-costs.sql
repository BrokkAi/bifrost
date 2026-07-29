-- Persist only the payload component that cannot be derived from blob_meta's
-- existing row counts. An absent row denotes either a migrated parsed blob
-- that still needs the indexed legacy fallback or a root-only blobs row; the
-- presence of blob_meta distinguishes those states. Do not seed this table
-- from the published v5 columns: legacy writes measured SQLite TEXT characters
-- rather than UTF-8 bytes, so a non-NULL v5 value is not known to be exact.
CREATE TABLE blob_payload_costs(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  payload_bytes  INTEGER NOT NULL CHECK(payload_bytes >= 0),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blob_meta(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
