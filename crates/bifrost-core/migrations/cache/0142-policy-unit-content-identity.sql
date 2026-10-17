-- Record which workspace snapshot each policy unit's name-index answers came
-- from (#3735).
--
-- A unit's name-index reads are proved by the set of names that moved between
-- two snapshots, which holds only for index answers of the first of them. A
-- unit therefore carries the content identity of the snapshot whose index
-- answers it read, and a base evaluation carries the identity of the base it
-- analyzed, so a later run verifies a unit's index reads only against what
-- moved since that snapshot.
--
-- Rows published before this migration carry no such identity and cannot be
-- told apart from a unit computed on any other snapshot. They are derived data
-- that the next run recomputes, so they are discarded rather than kept
-- unprovable. Children go first because the migration does not rely on
-- foreign-key cascades being enabled.
DELETE FROM policy_evaluation_units;
DELETE FROM policy_evaluation_identities;
DELETE FROM policy_evaluation_policies;
DELETE FROM policy_evaluations;
DELETE FROM policy_unit_reads;
DELETE FROM policy_units;
DELETE FROM policy_read_keys;

-- SQLite requires a default for a NOT NULL column added to an existing table.
-- Every writer supplies the identity; an all-zero value is not the digest of
-- any analyzed snapshot, so a row that somehow kept it is never reused.
ALTER TABLE policy_units ADD COLUMN content_identity BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(length(content_identity) = 32);

ALTER TABLE policy_evaluations ADD COLUMN base_content_identity BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(length(base_content_identity) = 32);
