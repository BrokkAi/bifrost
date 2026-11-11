-- Syntax-derived pattern projections are inert until selected declaration
-- authority proves constructor identity, field mapping and binding mode.
CREATE TABLE semantic_ir_guarded_pattern_projections(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  whole_value    INTEGER NOT NULL,
  binder         INTEGER NOT NULL,
  pattern_source INTEGER NOT NULL,
  binder_source  INTEGER NOT NULL,
  path_len       INTEGER NOT NULL CHECK(path_len BETWEEN 1 AND 16),
  status         INTEGER NOT NULL CHECK(status = 0),
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One ordinal or named field per candidate path segment. Exactly path_len
-- dense rows are required by the decoder before the candidate is exposed.
CREATE TABLE semantic_ir_guarded_pattern_steps(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  candidate     INTEGER NOT NULL,
  step          INTEGER NOT NULL,
  kind          INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  tuple_ordinal INTEGER,
  named_text    INTEGER,
  CHECK((kind = 0 AND tuple_ordinal IS NOT NULL AND named_text IS NULL) OR
        (kind = 1 AND tuple_ordinal IS NULL AND named_text IS NOT NULL)),
  PRIMARY KEY(blob_id, procedure, candidate, step),
  FOREIGN KEY(blob_id, procedure, candidate)
    REFERENCES semantic_ir_guarded_pattern_projections(blob_id, procedure, ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
