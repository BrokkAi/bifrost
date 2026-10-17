-- Completion vocabulary belongs to the policy producer, not the cache schema.
-- #4994: not_run and absent-run evidence must round-trip without an enum CHECK.
-- These derived evaluations are recomputed; separately keyed units survive.
DROP TABLE policy_evaluation_units;
DROP TABLE policy_evaluation_identities;
DROP TABLE policy_evaluation_policies;
DELETE FROM policy_evaluations;

CREATE TABLE policy_evaluation_policies(
  evaluation_id    INTEGER NOT NULL,
  policy_id        TEXT    NOT NULL CHECK(length(policy_id) > 0),
  source_hash      TEXT    NOT NULL
    CHECK(length(source_hash) = 64 AND source_hash NOT GLOB '*[^0-9a-f]*'),
  semantic_hash    TEXT    NOT NULL
    CHECK(length(semantic_hash) = 64 AND semantic_hash NOT GLOB '*[^0-9a-f]*'),
  completion       TEXT    NOT NULL CHECK(length(completion) > 0),
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
