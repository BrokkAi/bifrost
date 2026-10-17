-- #4967 adds the residual-conversion obligation (code 13). Preserve gap rows
-- while widening their vocabulary. No table references semantic_ir_gaps.
CREATE TABLE semantic_ir_gaps_next(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  gap              INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  subject          INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 7),
  subject_a        INTEGER,
  subject_b        INTEGER,
  capability       INTEGER NOT NULL CHECK(capability BETWEEN 0 AND 33),
  impacts          INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  budget_dimension INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit     INTEGER,
  budget_attempted INTEGER,
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 13),
  detail           INTEGER NOT NULL,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, gap),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO semantic_ir_gaps_next SELECT * FROM semantic_ir_gaps;
DROP TABLE semantic_ir_gaps;
ALTER TABLE semantic_ir_gaps_next RENAME TO semantic_ir_gaps;
