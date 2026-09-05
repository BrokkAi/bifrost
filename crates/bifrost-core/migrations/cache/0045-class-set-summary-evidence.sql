-- Replace the v44 class-set cache family with exact, lossless non-leaf
-- evidence. These rows are derived cache data and v44 never published
-- dependency or read evidence, so retaining its rows would make them look
-- complete under a stronger contract they did not satisfy.

DROP TABLE class_set_summary_charges;
DROP TABLE class_set_summary_reads;
DROP TABLE class_set_summary_dependencies;
DROP TABLE class_set_summary_reached;
DROP TABLE class_set_summary_exits;
DROP TABLE class_set_summary_facts;
DROP TABLE class_set_summaries;

CREATE TABLE class_set_summaries(
  summary_id                  INTEGER PRIMARY KEY,
  lookup_digest               BLOB    NOT NULL CHECK(length(lookup_digest) = 32),
  procedure_lineage           BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
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
  output_digest               BLOB    NOT NULL CHECK(length(output_digest) = 32),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at                INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(owner_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX class_set_summaries_lookup
  ON class_set_summaries(lookup_digest);
CREATE INDEX class_set_summaries_lineage
  ON class_set_summaries(procedure_lineage);
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
  summary_id                    INTEGER NOT NULL,
  dependency_ordinal            INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  callee_procedure_lineage      BLOB    NOT NULL CHECK(length(callee_procedure_lineage) = 32),
  callee_entry_selector_digest  BLOB    NOT NULL CHECK(length(callee_entry_selector_digest) = 32),
  expected_output_digest        BLOB    NOT NULL CHECK(length(expected_output_digest) = 32),
  consumed_child_lookup_digest  BLOB    NOT NULL CHECK(length(consumed_child_lookup_digest) = 32),
  PRIMARY KEY(summary_id, dependency_ordinal),
  UNIQUE(summary_id, consumed_child_lookup_digest),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX class_set_summary_dependencies_child_lookup
  ON class_set_summary_dependencies(consumed_child_lookup_digest, summary_id);
CREATE INDEX class_set_summary_dependencies_lineage_entry
  ON class_set_summary_dependencies(
    callee_procedure_lineage, callee_entry_selector_digest, summary_id
  );

CREATE TABLE class_set_summary_reads(
  summary_id   INTEGER NOT NULL,
  read_ordinal INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest   BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind         TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  family       TEXT,
  languages    TEXT,
  rel_path     TEXT,
  name         TEXT,
  index_key    BLOB,
  blob_oid     TEXT CHECK(blob_oid IS NULL OR
    (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  subject      BLOB CHECK(subject IS NULL OR length(subject) = 32),
  start_byte   INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte     INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  digest       BLOB CHECK(digest IS NULL OR length(digest) = 32),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK((kind = 'file') = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL)),
  CHECK(CASE kind
    WHEN 'file' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NOT NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'path_absent' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'index' THEN
      family IS NOT NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NOT NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'lookup' THEN
      family IS NOT NULL AND languages IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND digest IS NOT NULL AND (
        (rel_path IS NOT NULL AND name IS NOT NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NOT NULL AND end_byte IS NOT NULL)
        OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NULL AND end_byte IS NULL)
      )
    WHEN 'artifact' THEN
      family IS NOT NULL AND languages IS NULL AND name IS NULL AND index_key IS NULL
      AND blob_oid IS NULL AND subject IS NOT NULL AND start_byte IS NULL
      AND end_byte IS NULL AND digest IS NULL
    WHEN 'scope' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'policy' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NOT NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'models' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'configuration' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'epoch' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    ELSE 0
  END)
) WITHOUT ROWID, STRICT;

CREATE INDEX class_set_summary_reads_by_key
  ON class_set_summary_reads(key_digest, summary_id);

CREATE TABLE class_set_summary_charges(
  summary_id  INTEGER NOT NULL,
  charge_kind TEXT    NOT NULL CHECK(length(charge_kind) > 0),
  amount      INTEGER NOT NULL CHECK(amount > 0),
  PRIMARY KEY(summary_id, charge_kind),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
