-- Scala export clauses generate compiler aliases that are not represented by
-- source declarations. Persist their parser-backed selector facts with the
-- owning source unit so bulk usage-graph builds never need point hydration or
-- source reparsing.
CREATE TABLE scala_exports(
  blob_oid   TEXT    NOT NULL,
  lang       TEXT    NOT NULL,
  owner_key  INTEGER NOT NULL,
  ordinal    INTEGER NOT NULL,
  info       BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, owner_key, ordinal),
  FOREIGN KEY(blob_oid, lang, owner_key)
    REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
