-- The base evaluation's own answers: the strong finding identities one policy
-- set produced over one committed subtree.
--
-- Migration 0036 recorded a base evaluation as the units it published, and a
-- later run reconstructed the base's findings by merging those units and
-- replaying the adaptation over them. That works only for a family that has
-- per-partition units at all: a pack holding one taint or flow policy
-- publishes none for it, so the evaluation was never recordable and no run
-- against such a pack ever warmed
-- (`.agents/plans/impact-sliced-diff-base.md`, follow-up 3b).
--
-- What the diff join actually needs is not units but identities. Recording
-- them directly makes the warm path family-independent -- a taint policy's
-- base findings are as replayable as a match policy's -- and it removes the
-- replay's dependence on the base's scaled budget and merge order, because
-- there is no replay left. Units stay: they are what lets the *head* reuse the
-- base's per-file work, and `policy_evaluation_units` still names them so the
-- age sweep keeps a live evaluation's units.
--
-- Three columns and one column therefore lose their last reader, and dead
-- columns in a schema are a claim nobody checks. `policy_evaluations` drops
-- `unit_count` (which existed so a reader could tell a partial unit set from a
-- whole one before merging it), `analyzed_source_bytes` and
-- `analyzed_file_count` (which existed so a replay could scale the budget the
-- base was scaled to); `policy_evaluation_units` drops `ordinal` (which
-- existed so the merge could walk the units in the order the base merged
-- them).
--
-- No row is carried across. An evaluation written before this migration has no
-- identities, and an identity set that is absent is indistinguishable from one
-- that is empty: a run that reused such a row would report every head finding
-- as new and every base finding as absent. Recreating both tables empty is
-- what makes "an evaluation row is authoritative about its own identities"
-- true by construction rather than by a column that says so. The units survive
-- in `policy_units`, keyed by content, so nothing that is still valid is
-- thrown away -- the next run re-records the evaluation over units it does not
-- have to recompute.
--
-- Children before parents: the migration chain runs with `PRAGMA foreign_keys`
-- ON, under which `DROP TABLE` fires the cascades of the rows it removes.

DROP TABLE policy_evaluation_units;
DROP TABLE policy_evaluations;

-- One completed base evaluation of one policy set over one committed subtree.
--
-- The tree oid determines the base bytes exactly, including a subdirectory
-- root; the other key columns carry the inputs a tree id does not: which
-- policies were evaluated, under which options, analyzer configuration, active
-- semantic-model set, and analysis epoch. A row exists only for an evaluation
-- that was reliable and whose every policy ran exhaustively, because that is
-- the only kind whose findings a later run may substitute for evaluating the
-- base again.
CREATE TABLE policy_evaluations(
  evaluation_id             INTEGER PRIMARY KEY,
  base_tree_oid             TEXT    NOT NULL
    CHECK(length(base_tree_oid) = 40 AND base_tree_oid NOT GLOB '*[^0-9a-f]*'),
  policy_set_digest         TEXT    NOT NULL
    CHECK(length(policy_set_digest) = 64 AND policy_set_digest NOT GLOB '*[^0-9a-f]*'),
  options_digest            TEXT    NOT NULL
    CHECK(length(options_digest) = 64 AND options_digest NOT GLOB '*[^0-9a-f]*'),
  configuration_fingerprint TEXT    NOT NULL
    CHECK(length(configuration_fingerprint) = 64
          AND configuration_fingerprint NOT GLOB '*[^0-9a-f]*'),
  active_model_set_hash     TEXT    NOT NULL
    CHECK(length(active_model_set_hash) = 64
          AND active_model_set_hash NOT GLOB '*[^0-9a-f]*'),
  engine_epoch              TEXT    NOT NULL
    CHECK(length(engine_epoch) = 64 AND engine_epoch NOT GLOB '*[^0-9a-f]*'),
  resolved_commit           TEXT    NOT NULL
    CHECK(length(resolved_commit) = 40 AND resolved_commit NOT GLOB '*[^0-9a-f]*'),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0)
) STRICT;

CREATE UNIQUE INDEX policy_evaluations_key ON policy_evaluations(
  base_tree_oid,
  policy_set_digest,
  options_digest,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch
);

CREATE INDEX policy_evaluations_published_at ON policy_evaluations(published_at);

-- The units one evaluation published, per policy.
--
-- A membership is not how the base's findings are recovered any more; it is
-- how the age sweep tells a unit that belongs to a live base evaluation from
-- one no evaluation names. A policy that published no unit -- a whole-policy
-- family, a widened evaluation -- simply has no row here, which is why this
-- table can no longer make an evaluation unrecordable.
CREATE TABLE policy_evaluation_units(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  unit_id       INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, policy_id, unit_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE,
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX policy_evaluation_units_by_unit ON policy_evaluation_units(unit_id);

-- The strong finding identities one base evaluation produced, per policy.
--
-- This is exactly the set the diff join holds in memory during a cold run: the
-- head's findings are classified against it, and the base identities no head
-- finding claimed are the fixed list. Weak identities are snapshot-local by
-- construction and never enter it.
--
-- `finding_id` is the 32-byte identity digest itself rather than its hex
-- spelling: it is compared for equality and nothing else, and the schema
-- checks its width so a truncated digest cannot become a finding that matches
-- nothing.
--
-- The primary key is the read path. It is `WITHOUT ROWID`, so the key IS the
-- storage and a per-evaluation-and-policy read seeks it directly on its
-- leading columns; a separate index over the same prefix would be a second
-- copy of the same b-tree. The evaluation's own cascade uses the same prefix.
CREATE TABLE policy_evaluation_identities(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  finding_id    BLOB    NOT NULL CHECK(length(finding_id) = 32),
  PRIMARY KEY(evaluation_id, policy_id, finding_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
