-- #11607: what an aggregate evaluation's selection reads were taken over.
-- selection_export_tree is the tree id of the revision export the evaluation's
-- analyzer was built over; NULL means a live worktree. A read that is a
-- function of the exported tree is replayed only for an export of the key's
-- tree. basis_platform_override is non-NULL for a read recorded with the tree
-- part of a JVM dependency selection, and its coordinate rows hold what the
-- manifests declared, so replay can resolve them again in its own environment.
-- The migration runner supplies the transaction and disables foreign keys.
ALTER TABLE policy_evaluations ADD COLUMN selection_export_tree TEXT;
ALTER TABLE policy_evaluation_reads ADD COLUMN basis_platform_override INTEGER
  CHECK(basis_platform_override IN (0, 1));
CREATE TABLE policy_evaluation_read_coordinates(
  evaluation_id INTEGER NOT NULL,
  read_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL,
  group_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  version TEXT NOT NULL,
  scope TEXT NOT NULL,
  declared_by TEXT,
  PRIMARY KEY(evaluation_id, read_id, ordinal),
  FOREIGN KEY(evaluation_id, read_id)
    REFERENCES policy_evaluation_reads(evaluation_id, read_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
