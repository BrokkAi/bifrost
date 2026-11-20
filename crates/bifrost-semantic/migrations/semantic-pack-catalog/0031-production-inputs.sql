-- BREAKING: v30 binaries ignore production selectors and cannot copy input rows.
-- The existing user_version fence rejects this catalog before any writer opens it.
ALTER TABLE catalog_selectors ADD COLUMN production_input_digest TEXT
 CHECK(production_input_digest IS NULL OR (length(production_input_digest)=64 AND production_input_digest NOT GLOB '*[^0-9a-f]*'));
CREATE INDEX catalog_selectors_production_input ON catalog_selectors(production_input_digest);
CREATE TABLE catalog_production_inputs (
 production_digest TEXT NOT NULL REFERENCES catalog_generated_productions(production_digest) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
 slot_count INTEGER NOT NULL CHECK(slot_count > 0 AND ordinal < slot_count),
 role TEXT NOT NULL,
 kind TEXT NOT NULL,
 module TEXT,
 sha256 BLOB NOT NULL CHECK(length(sha256)=32),
 PRIMARY KEY(production_digest, ordinal)
) WITHOUT ROWID, STRICT;
