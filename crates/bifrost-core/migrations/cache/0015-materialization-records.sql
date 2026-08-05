-- Declaration-materialization provenance (issue #1476): generation sites and
-- their generated units, dynamic generation sites, export declarations,
-- recovered declarations, and preprocessor-conditional intervals, recorded by
-- the language walk that created the declarations they describe.
--
-- One row per record, in recording order. `unit_key` names the one unit a
-- record references (the generated/recovered declaration, an export's local
-- target) and is NULL for records that name no unit (a dynamic generation
-- site, a configuration interval, a target-less export). `payload` is the
-- serialized language-neutral remainder
-- (bifrost-core `MaterializationRecordPayload`).
CREATE TABLE materialization_records(
  blob_oid TEXT    NOT NULL,
  lang     TEXT    NOT NULL,
  ordinal  INTEGER NOT NULL,
  unit_key INTEGER,
  payload  BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
