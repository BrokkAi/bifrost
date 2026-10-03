-- Store complete diff-base findings as independently qualified policy rows.
--
-- The old policy-set digest made one policy's source identity part of every
-- other policy's lookup key. Its identity rows also had no completion or
-- policy-dependency provenance. Those derived evaluations cannot be promoted
-- safely, so discard them while preserving the separately keyed policy units.
DROP TABLE policy_evaluation_units;
DROP TABLE policy_evaluation_identities;
DROP TABLE policy_evaluations;

CREATE TABLE policy_evaluations(
  evaluation_id             INTEGER PRIMARY KEY,
  base_tree_oid             TEXT    NOT NULL
    CHECK(length(base_tree_oid) = 40 AND base_tree_oid NOT GLOB '*[^0-9a-f]*'),
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
  policy_set_digest         TEXT    NOT NULL
    CHECK(length(policy_set_digest) = 64
          AND policy_set_digest NOT GLOB '*[^0-9a-f]*')
    DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
  unreliable_detail         TEXT,
  aggregate_unreliable      INTEGER NOT NULL DEFAULT 0
    CHECK(aggregate_unreliable IN (0, 1)),
  resolved_commit           TEXT    NOT NULL
    CHECK(length(resolved_commit) = 40 AND resolved_commit NOT GLOB '*[^0-9a-f]*'),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0)
) STRICT;

CREATE UNIQUE INDEX policy_evaluations_key ON policy_evaluations(
  base_tree_oid,
  options_digest,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch
);

CREATE INDEX policy_evaluations_published_at ON policy_evaluations(published_at);

CREATE TABLE policy_evaluation_policies(
  evaluation_id    INTEGER NOT NULL,
  policy_id        TEXT    NOT NULL CHECK(length(policy_id) > 0),
  source_hash      TEXT    NOT NULL
    CHECK(length(source_hash) = 64 AND source_hash NOT GLOB '*[^0-9a-f]*'),
  semantic_hash    TEXT    NOT NULL
    CHECK(length(semantic_hash) = 64 AND semantic_hash NOT GLOB '*[^0-9a-f]*'),
  completion       TEXT    NOT NULL CHECK(completion IN (
                            'complete', 'proven_subset', 'proven_by_summary',
                            'inconclusive', 'unsupported', 'failed')),
  completion_detail TEXT   NOT NULL CHECK(json_valid(completion_detail)),
  qualified         INTEGER NOT NULL CHECK(qualified IN (0, 1)
                                  AND (qualified = 0 OR completion = 'complete')),
  qualification_detail TEXT NOT NULL,
  diagnostics      TEXT    NOT NULL
    CHECK(json_valid(diagnostics) AND json_type(diagnostics) = 'array'),
  CHECK((qualified = 1 AND qualification_detail = '')
     OR (qualified = 0 AND length(qualification_detail) > 0)),
  PRIMARY KEY(evaluation_id, policy_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE policy_evaluation_identities(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  finding_id    BLOB    NOT NULL CHECK(length(finding_id) = 32),
  PRIMARY KEY(evaluation_id, policy_id, finding_id),
  FOREIGN KEY(evaluation_id, policy_id)
    REFERENCES policy_evaluation_policies(evaluation_id, policy_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TRIGGER policy_evaluation_identities_require_qualified_insert
BEFORE INSERT ON policy_evaluation_identities
WHEN NOT EXISTS (
  SELECT 1 FROM policy_evaluation_policies
  WHERE evaluation_id = NEW.evaluation_id AND policy_id = NEW.policy_id
    AND completion = 'complete' AND qualified = 1
)
BEGIN
  SELECT RAISE(ABORT, 'policy finding identities require qualified complete evidence');
END;

CREATE TRIGGER policy_evaluation_identities_require_qualified_update
BEFORE UPDATE OF completion, qualified ON policy_evaluation_policies
WHEN (NEW.completion <> 'complete' OR NEW.qualified <> 1)
  AND EXISTS (
    SELECT 1 FROM policy_evaluation_identities
    WHERE evaluation_id = OLD.evaluation_id AND policy_id = OLD.policy_id
  )
BEGIN
  SELECT RAISE(ABORT, 'policy finding identities require qualified complete evidence');
END;

CREATE TABLE policy_evaluation_units(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  unit_id       INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, policy_id, unit_id),
  FOREIGN KEY(evaluation_id, policy_id)
    REFERENCES policy_evaluation_policies(evaluation_id, policy_id) ON DELETE CASCADE,
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX policy_evaluation_units_by_unit ON policy_evaluation_units(unit_id);
