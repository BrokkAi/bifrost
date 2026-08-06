-- Keep counts for optional analyzer facts only when a blob has those facts.
-- Fact-kind values are stable persistence identifiers:
--   1 = C++ template metadata
--   2 = Ruby method dispatch modes
--   3 = Scala traits
--   4 = Scala exports
--   5 = declaration materialization records
-- Rebuild blob_meta without analyzer-specific count columns. Rebuild its two
-- child tables in the same transaction so populated version-15 rows survive.
CREATE TABLE blob_meta_new(
  blob_oid                   TEXT    NOT NULL,
  lang                       TEXT    NOT NULL,
  contains_tests             INTEGER NOT NULL CHECK(contains_tests IN (0, 1)),
  content_package            TEXT    NOT NULL,
  stored_unit_count          INTEGER NOT NULL CHECK(stored_unit_count >= 0),
  range_count                INTEGER NOT NULL CHECK(range_count >= 0),
  signature_count            INTEGER NOT NULL CHECK(signature_count >= 0),
  signature_metadata_count   INTEGER NOT NULL CHECK(signature_metadata_count >= 0),
  supertype_count            INTEGER NOT NULL CHECK(supertype_count >= 0),
  child_count                INTEGER NOT NULL CHECK(child_count >= 0),
  import_statement_count     INTEGER NOT NULL CHECK(import_statement_count >= 0),
  import_count               INTEGER NOT NULL CHECK(import_count >= 0),
  type_identifier_count      INTEGER NOT NULL CHECK(type_identifier_count >= 0),
  is_complete                INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_meta_new(
  blob_oid, lang, contains_tests, content_package, stored_unit_count,
  range_count, signature_count, signature_metadata_count, supertype_count,
  child_count, import_statement_count, import_count, type_identifier_count,
  is_complete
)
SELECT
  blob_oid, lang, contains_tests, content_package, stored_unit_count,
  range_count, signature_count, signature_metadata_count, supertype_count,
  child_count, import_statement_count, import_count, type_identifier_count,
  is_complete
FROM blob_meta;

CREATE TABLE blob_optional_fact_manifest(
  blob_oid   TEXT    NOT NULL,
  lang       TEXT    NOT NULL,
  fact_kind  INTEGER NOT NULL CHECK(fact_kind > 0),
  row_count  INTEGER NOT NULL CHECK(row_count > 0),
  PRIMARY KEY(blob_oid, lang, fact_kind),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blob_meta_new(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The first three counts existed in blob_meta before this migration. Preserve
-- their declared values so a pre-existing mismatch remains detectable.
INSERT INTO blob_optional_fact_manifest(blob_oid, lang, fact_kind, row_count)
SELECT blob_oid, lang, 1, cpp_template_metadata_count
FROM blob_meta
WHERE cpp_template_metadata_count > 0;

INSERT INTO blob_optional_fact_manifest(blob_oid, lang, fact_kind, row_count)
SELECT blob_oid, lang, 2, ruby_dispatch_count
FROM blob_meta
WHERE ruby_dispatch_count > 0;

INSERT INTO blob_optional_fact_manifest(blob_oid, lang, fact_kind, row_count)
SELECT blob_oid, lang, 3, scala_trait_count
FROM blob_meta
WHERE scala_trait_count > 0;

-- Scala exports and materialization records did not have integrity counts.
-- Seed their counts from the rows that migration 0016 must preserve.
INSERT INTO blob_optional_fact_manifest(blob_oid, lang, fact_kind, row_count)
SELECT facts.blob_oid, facts.lang, 4, COUNT(*)
FROM scala_exports AS facts
INNER JOIN blob_meta AS meta
  ON meta.blob_oid = facts.blob_oid AND meta.lang = facts.lang
GROUP BY facts.blob_oid, facts.lang;

INSERT INTO blob_optional_fact_manifest(blob_oid, lang, fact_kind, row_count)
SELECT facts.blob_oid, facts.lang, 5, COUNT(*)
FROM materialization_records AS facts
INNER JOIN blob_meta AS meta
  ON meta.blob_oid = facts.blob_oid AND meta.lang = facts.lang
GROUP BY facts.blob_oid, facts.lang;

CREATE TABLE blob_payload_costs_new(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  payload_bytes  INTEGER NOT NULL CHECK(payload_bytes >= 0),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blob_meta_new(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO blob_payload_costs_new(blob_oid, lang, payload_bytes)
SELECT blob_oid, lang, payload_bytes
FROM blob_payload_costs;

CREATE TABLE structural_facts_snapshots_new(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  snapshot_version  INTEGER NOT NULL CHECK(snapshot_version > 0),
  payload           BLOB    NOT NULL,
  PRIMARY KEY(blob_oid, lang, snapshot_version),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blob_meta_new(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO structural_facts_snapshots_new(
  blob_oid, lang, snapshot_version, payload
)
SELECT blob_oid, lang, snapshot_version, payload
FROM structural_facts_snapshots;

DROP TABLE structural_facts_snapshots;
DROP TABLE blob_payload_costs;
DROP TABLE blob_meta;

ALTER TABLE blob_meta_new RENAME TO blob_meta;
ALTER TABLE blob_payload_costs_new RENAME TO blob_payload_costs;
ALTER TABLE structural_facts_snapshots_new RENAME TO structural_facts_snapshots;
