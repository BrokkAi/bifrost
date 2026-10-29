-- Record every snapshot a policy unit's name-index answers hold on (#7426).
--
-- A unit's name-index reads are proved by the set of names that moved between
-- two snapshots, which holds only for index answers of the first of them.
-- Migration 0142 stamped each unit with one such snapshot. A check that reuses
-- a unit proves its answers hold on the check's head too, and a unit computed
-- on a head whose probes avoid every moved name holds on the base as well. One
-- stamp could keep only one of those, so a chain of checks (each based on the
-- previous head) recomputed every name-index unit the chain had reused.
--
-- `attestation` numbers a unit's attestations in the order they were made,
-- so the writer can keep the most recent ones and drop the rest. A clock
-- would tie within one run.
CREATE TABLE policy_unit_snapshots(
  unit_id          INTEGER NOT NULL,
  content_identity BLOB    NOT NULL CHECK(length(content_identity) = 32),
  attestation      INTEGER NOT NULL CHECK(attestation >= 1),
  PRIMARY KEY(unit_id, content_identity),
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO policy_unit_snapshots(unit_id, content_identity, attestation)
SELECT unit_id, content_identity, 1 FROM policy_units;

ALTER TABLE policy_units DROP COLUMN content_identity;
