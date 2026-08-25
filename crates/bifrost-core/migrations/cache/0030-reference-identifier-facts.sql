-- Generalize the parsed identifier relation into the shared reference-planning
-- fact family. The stored rows are unchanged, so every existing blob remains
-- reusable; only the table and column names stop claiming that all languages
-- record types exclusively.

DROP INDEX idx_type_identifiers_by_identifier;
ALTER TABLE type_identifiers RENAME TO reference_identifiers;
ALTER TABLE reference_identifiers RENAME COLUMN type_identifier TO identifier;

CREATE INDEX idx_reference_identifiers_by_identifier
  ON reference_identifiers(lang, identifier, blob_oid);

-- Reference facts evolve independently from declarations and the other parse
-- products. A future extractor epoch can leave every unrelated blob row warm
-- and reconcile only live blobs whose manifest is absent or stale.
CREATE TABLE reference_fact_epochs(
  lang   TEXT    PRIMARY KEY,
  epoch  INTEGER NOT NULL CHECK(epoch > 0)
) WITHOUT ROWID, STRICT;

CREATE TABLE blob_reference_fact_manifests(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  epoch             INTEGER NOT NULL CHECK(epoch > 0),
  identifier_count  INTEGER NOT NULL CHECK(identifier_count >= 0),
  PRIMARY KEY(blob_oid, lang),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Epoch 1 is exactly the identifier semantics the pre-v30 writers produced,
-- so this is a lossless SQL migration rather than a source-backed rebuild.
INSERT INTO reference_fact_epochs(lang, epoch)
SELECT DISTINCT lang, 1 FROM blobs;

INSERT INTO blob_reference_fact_manifests(blob_oid, lang, epoch, identifier_count)
SELECT blob_oid, lang, 1, type_identifier_count
FROM blob_meta
WHERE is_complete = 1;
