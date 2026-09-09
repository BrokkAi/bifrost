-- Persist the bounded syntactic field-store survey beside complete field slots.
-- Existing representation-1 rows remain available with an empty survey; the
-- field-slot flow rotates its representation before consuming this evidence.

ALTER TABLE class_set_field_slot_indexes
  ADD COLUMN store_survey_count INTEGER NOT NULL DEFAULT 0
    CHECK(store_survey_count >= 0);

ALTER TABLE class_set_field_slot_indexes
  ADD COLUMN store_survey_unknown_members INTEGER NOT NULL DEFAULT 0
    CHECK(store_survey_unknown_members IN (0, 1));

CREATE TABLE class_set_field_slot_stores (
  index_id             INTEGER NOT NULL
    REFERENCES class_set_field_slot_indexes(index_id) ON DELETE CASCADE,
  store_ordinal        INTEGER NOT NULL CHECK(store_ordinal >= 0),
  owner_kind           TEXT,
  owner_declaration_id TEXT,
  owner_fq_name        TEXT,
  owner_rel_path       TEXT,
  owner_symbol_id      TEXT,
  member               TEXT NOT NULL,
  PRIMARY KEY(index_id, store_ordinal),
  CHECK(owner_kind IS NULL OR owner_kind IN ('workspace', 'external')),
  CHECK(
    (owner_kind IS NULL AND owner_declaration_id IS NULL
                         AND owner_fq_name IS NULL
                         AND owner_rel_path IS NULL
                         AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'workspace' AND owner_declaration_id IS NOT NULL
                              AND owner_fq_name IS NOT NULL
                              AND owner_rel_path IS NOT NULL
                              AND owner_symbol_id IS NULL)
    OR
    (owner_kind = 'external' AND owner_declaration_id IS NULL
                             AND owner_fq_name IS NOT NULL
                             AND owner_rel_path IS NULL
                             AND owner_symbol_id IS NOT NULL)
  )
) STRICT;
