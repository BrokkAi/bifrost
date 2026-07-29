CREATE TABLE path_symbol_units(
  lang            TEXT NOT NULL,
  rel_path        TEXT NOT NULL,
  blob_oid        TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  kind            INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
  package_name    TEXT NOT NULL,
  short_name      TEXT NOT NULL,
  exact_fqn       TEXT NOT NULL,
  normalized_fqn  TEXT NOT NULL,
  PRIMARY KEY(lang, rel_path, kind, exact_fqn)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_path_symbol_units_lang_exact_fqn
  ON path_symbol_units(lang, exact_fqn);
CREATE INDEX idx_path_symbol_units_lang_normalized_fqn
  ON path_symbol_units(lang, normalized_fqn);

ALTER TABLE unit_supertypes
  ADD COLUMN lookup_path TEXT NOT NULL DEFAULT '';

-- Supertype lookup paths are structured parser facts. Existing blob rows do
-- not contain them, so invalidate the rebuildable blob cache once rather than
-- deriving paths from persisted display text at request time.
DELETE FROM blobs;
