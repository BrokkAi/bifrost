-- Dependency entry selectors became source-behavior-sensitive in schema v50.
-- Version 49 rows do not retain enough material to reconstruct or validate
-- that selector after the consumed child row disappears. Class-set summaries
-- are derived cache data, so discard them and replace only their dependency
-- evidence tables with the complete descriptor and exact source witnesses.

DELETE FROM class_set_summaries;

DROP TABLE class_set_summary_dependencies;

CREATE TABLE class_set_summary_dependencies(
  summary_id                    INTEGER NOT NULL,
  dependency_ordinal            INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  callee_procedure_lineage      BLOB    NOT NULL CHECK(length(callee_procedure_lineage) = 32),
  callee_entry_selector_digest  BLOB    NOT NULL CHECK(length(callee_entry_selector_digest) = 32),
  expected_output_digest        BLOB    NOT NULL CHECK(length(expected_output_digest) = 32),
  consumed_child_lookup_digest  BLOB    NOT NULL CHECK(length(consumed_child_lookup_digest) = 32),
  entry_kind                    TEXT    NOT NULL CHECK(entry_kind IN ('zero', 'carrier')),
  entry_carrier_key             BLOB CHECK(entry_carrier_key IS NULL OR length(entry_carrier_key) = 32),
  entry_uncertain               INTEGER NOT NULL CHECK(entry_uncertain IN (0, 1)),
  entry_source_behavior_digest  BLOB CHECK(entry_source_behavior_digest IS NULL OR length(entry_source_behavior_digest) = 32),
  entry_source_count            INTEGER NOT NULL CHECK(entry_source_count >= 0),
  PRIMARY KEY(summary_id, dependency_ordinal),
  UNIQUE(summary_id, consumed_child_lookup_digest),
  CHECK(
    (entry_kind = 'zero' AND entry_carrier_key IS NULL AND entry_uncertain = 0
      AND entry_source_behavior_digest IS NULL AND entry_source_count = 0)
    OR
    (entry_kind = 'carrier' AND entry_carrier_key IS NOT NULL AND entry_source_count > 0)
  ),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX class_set_summary_dependencies_child_lookup
  ON class_set_summary_dependencies(consumed_child_lookup_digest, summary_id);
CREATE INDEX class_set_summary_dependencies_lineage_entry
  ON class_set_summary_dependencies(
    callee_procedure_lineage, callee_entry_selector_digest, summary_id
  );

CREATE TABLE class_set_summary_dependency_sources(
  summary_id         INTEGER NOT NULL,
  dependency_ordinal INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  source_ordinal     INTEGER NOT NULL CHECK(source_ordinal >= 0),
  source_event_digest BLOB NOT NULL CHECK(length(source_event_digest) = 32),
  PRIMARY KEY(summary_id, dependency_ordinal, source_ordinal),
  UNIQUE(summary_id, dependency_ordinal, source_event_digest),
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES class_set_summary_dependencies(summary_id, dependency_ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
