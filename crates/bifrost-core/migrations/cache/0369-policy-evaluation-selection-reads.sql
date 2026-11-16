-- #11482: the selection-authority reads an aggregate evaluation consumed.
-- Rows reuse the policy_read_keys interning that policy units use. The
-- migration runner supplies the transaction and disables foreign keys.
CREATE TABLE policy_evaluation_reads(
  evaluation_id INTEGER NOT NULL,
  read_id INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, read_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE,
  FOREIGN KEY(read_id) REFERENCES policy_read_keys(read_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX policy_evaluation_reads_by_read ON policy_evaluation_reads(read_id);
