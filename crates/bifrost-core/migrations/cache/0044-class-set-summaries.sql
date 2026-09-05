-- Persisted, complete class-set procedure summaries.
--
-- The summary header carries only identity and admission metadata. Queryable
-- relation structure remains normalized in child tables. Canonical carrier
-- and event keys are bytes defined by the class-set producer, not serialized
-- Rust values; their kinds and roles remain explicit columns.

CREATE TABLE class_set_summaries(
  summary_id                  INTEGER PRIMARY KEY,
  lookup_digest               BLOB    NOT NULL CHECK(length(lookup_digest) = 32),
  procedure_read_identity     BLOB    NOT NULL CHECK(length(procedure_read_identity) = 32),
  owner_rel_path              TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id               INTEGER NOT NULL,
  lang                        TEXT    NOT NULL,
  artifact_public_identity    BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity   BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version              INTEGER NOT NULL CHECK(schema_version > 0),
  semantics_digest            BLOB    NOT NULL CHECK(length(semantics_digest) = 32),
  context_digest              BLOB    NOT NULL CHECK(length(context_digest) = 32),
  behavior_read_digest        BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  dependency_digest           BLOB    NOT NULL CHECK(length(dependency_digest) = 32),
  carrier_digest              BLOB    NOT NULL CHECK(length(carrier_digest) = 32),
  field_slots_digest          BLOB    NOT NULL CHECK(length(field_slots_digest) = 32),
  entry_fact_ordinal          INTEGER NOT NULL CHECK(entry_fact_ordinal >= 0),
  fact_count                  INTEGER NOT NULL CHECK(fact_count >= 1),
  exit_count                  INTEGER NOT NULL CHECK(exit_count >= 1),
  reached_count               INTEGER NOT NULL CHECK(reached_count >= 0),
  dependency_count            INTEGER NOT NULL CHECK(dependency_count >= 0),
  read_count                  INTEGER NOT NULL CHECK(read_count >= 0),
  charge_count                INTEGER NOT NULL CHECK(charge_count >= 1),
  completion                  TEXT    NOT NULL CHECK(completion = 'complete'),
  budget_mode                 TEXT    NOT NULL CHECK(budget_mode = 'exhaustive'),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at                INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX class_set_summaries_lookup
  ON class_set_summaries(lookup_digest);
CREATE INDEX class_set_summaries_procedure
  ON class_set_summaries(procedure_read_identity);
CREATE INDEX class_set_summaries_owner_blob
  ON class_set_summaries(owner_blob_id, lang);

CREATE TABLE class_set_summary_facts(
  summary_id       INTEGER NOT NULL,
  fact_ordinal     INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  fact_kind        TEXT    NOT NULL CHECK(fact_kind IN ('zero', 'carrier', 'meeting')),
  source_kind      TEXT    NOT NULL CHECK(source_kind IN ('none', 'entry', 'event')),
  source_event_key BLOB,
  carrier_key      BLOB,
  sink_event_key   BLOB,
  uncertain        INTEGER NOT NULL CHECK(uncertain IN (0, 1)),
  PRIMARY KEY(summary_id, fact_ordinal),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK((source_kind = 'event') = (source_event_key IS NOT NULL)),
  CHECK(source_event_key IS NULL OR length(source_event_key) = 32),
  CHECK(carrier_key IS NULL OR length(carrier_key) = 32),
  CHECK(sink_event_key IS NULL OR length(sink_event_key) = 32),
  CHECK((fact_kind = 'zero') =
        (source_kind = 'none' AND carrier_key IS NULL AND sink_event_key IS NULL)),
  CHECK((fact_kind = 'carrier') = (carrier_key IS NOT NULL)),
  CHECK((fact_kind = 'meeting') = (sink_event_key IS NOT NULL)),
  CHECK(fact_kind = 'zero' OR source_kind <> 'none'),
  CHECK(fact_kind <> 'zero' OR uncertain = 0)
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_summary_exits(
  summary_id      INTEGER NOT NULL,
  exit_ordinal    INTEGER NOT NULL CHECK(exit_ordinal >= 0),
  exit_kind       TEXT    NOT NULL CHECK(exit_kind IN ('normal', 'exceptional')),
  fact_ordinal    INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  quality_mask    INTEGER NOT NULL CHECK(quality_mask IN (1, 2, 4, 6, 8)),
  PRIMARY KEY(summary_id, exit_ordinal),
  FOREIGN KEY(summary_id, fact_ordinal)
    REFERENCES class_set_summary_facts(summary_id, fact_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_summary_reached(
  summary_id      INTEGER NOT NULL,
  reached_ordinal INTEGER NOT NULL CHECK(reached_ordinal >= 0),
  point_id        INTEGER NOT NULL CHECK(point_id >= 0),
  fact_ordinal    INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  quality_mask    INTEGER NOT NULL CHECK(quality_mask IN (1, 2, 4, 6, 8)),
  PRIMARY KEY(summary_id, reached_ordinal),
  FOREIGN KEY(summary_id, fact_ordinal)
    REFERENCES class_set_summary_facts(summary_id, fact_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_summary_dependencies(
  summary_id               INTEGER NOT NULL,
  dependency_ordinal       INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  procedure_read_identity  BLOB    NOT NULL CHECK(length(procedure_read_identity) = 32),
  summary_digest           BLOB    NOT NULL CHECK(length(summary_digest) = 32),
  PRIMARY KEY(summary_id, dependency_ordinal),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX class_set_summary_dependencies_procedure
  ON class_set_summary_dependencies(procedure_read_identity);

CREATE TABLE class_set_summary_reads(
  summary_id   INTEGER NOT NULL,
  read_ordinal INTEGER NOT NULL CHECK(read_ordinal >= 0),
  read_kind    TEXT    NOT NULL CHECK(length(read_kind) > 0),
  key_digest   BLOB    NOT NULL CHECK(length(key_digest) = 32),
  value_digest BLOB    NOT NULL CHECK(length(value_digest) = 32),
  PRIMARY KEY(summary_id, read_ordinal),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE class_set_summary_charges(
  summary_id INTEGER NOT NULL,
  charge_kind TEXT   NOT NULL CHECK(length(charge_kind) > 0),
  amount      INTEGER NOT NULL CHECK(amount > 0),
  PRIMARY KEY(summary_id, charge_kind),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
