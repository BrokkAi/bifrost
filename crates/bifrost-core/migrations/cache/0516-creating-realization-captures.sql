-- #13854. Reader-breaking: new capture discharge discriminant; fenced by user_version.
-- Preserve gap dependents with foreign keys enabled as well as disabled.

CREATE TEMP TABLE _capture_semantic_ir_call_control_obligations AS SELECT * FROM semantic_ir_call_control_obligations;

CREATE TEMP TABLE _capture_semantic_ir_footprint_call_target_obligations AS SELECT * FROM semantic_ir_footprint_call_target_obligations;

CREATE TEMP TABLE _capture_candidate_macro_semantic_ir_call_control_obligations AS SELECT * FROM candidate_macro_semantic_ir_call_control_obligations;

CREATE TEMP TABLE _capture_candidate_macro_semantic_ir_footprint_call_target_obligations AS SELECT * FROM candidate_macro_semantic_ir_footprint_call_target_obligations;

CREATE TEMP TABLE _capture_semantic_ir_gaps AS SELECT * FROM semantic_ir_gaps;

CREATE TEMP TABLE _capture_candidate_macro_semantic_ir_gaps AS SELECT * FROM candidate_macro_semantic_ir_gaps;

DELETE FROM semantic_ir_call_control_obligations;

DELETE FROM semantic_ir_footprint_call_target_obligations;

DELETE FROM candidate_macro_semantic_ir_call_control_obligations;

DELETE FROM candidate_macro_semantic_ir_footprint_call_target_obligations;

DROP TABLE semantic_ir_gaps;

CREATE TABLE "semantic_ir_gaps"(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  gap              INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  subject          INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 10),
  subject_a        INTEGER,
  subject_b        INTEGER,
  capability       INTEGER NOT NULL CHECK(capability BETWEEN 0 AND 33),
  impacts          INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  budget_dimension INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit     INTEGER,
  budget_attempted INTEGER,
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 16),
  detail           INTEGER NOT NULL,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  -- Inclusive cleanup segment head; NULL denotes the empty sentinel.
  segment_head INTEGER,
  -- Exclusive ancestor stop; NULL walks through the root.
  segment_stop INTEGER,
  CHECK(subject = 8 OR (segment_head IS NULL AND segment_stop IS NULL)),
  CHECK(segment_stop IS NULL OR segment_head IS NOT NULL),
  CHECK(subject != 8 OR (subject_a IS NULL AND subject_b IS NULL)),
  FOREIGN KEY(blob_id, procedure, segment_head) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, segment_stop) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node),
  PRIMARY KEY(blob_id, procedure, gap),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE candidate_macro_semantic_ir_gaps;

CREATE TABLE "candidate_macro_semantic_ir_gaps"(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  gap              INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  subject          INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 10),
  subject_a        INTEGER,
  subject_b        INTEGER,
  capability       INTEGER NOT NULL CHECK(capability BETWEEN 0 AND 33),
  impacts          INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  budget_dimension INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit     INTEGER,
  budget_attempted INTEGER,
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 16),
  detail           INTEGER NOT NULL,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  -- Inclusive cleanup segment head; NULL denotes the empty sentinel.
  segment_head INTEGER,
  -- Exclusive ancestor stop; NULL walks through the root.
  segment_stop INTEGER,
  CHECK(subject = 8 OR (segment_head IS NULL AND segment_stop IS NULL)),
  CHECK(segment_stop IS NULL OR segment_head IS NOT NULL),
  CHECK(subject != 8 OR (subject_a IS NULL AND subject_b IS NULL)),
  FOREIGN KEY(blob_id, procedure, segment_head) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, segment_stop) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node),
  PRIMARY KEY(blob_id, procedure, gap),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO semantic_ir_gaps SELECT * FROM _capture_semantic_ir_gaps;

DROP TABLE _capture_semantic_ir_gaps;

INSERT INTO candidate_macro_semantic_ir_gaps SELECT * FROM _capture_candidate_macro_semantic_ir_gaps;

DROP TABLE _capture_candidate_macro_semantic_ir_gaps;

INSERT INTO semantic_ir_call_control_obligations SELECT * FROM _capture_semantic_ir_call_control_obligations;

DROP TABLE _capture_semantic_ir_call_control_obligations;

INSERT INTO semantic_ir_footprint_call_target_obligations SELECT * FROM _capture_semantic_ir_footprint_call_target_obligations;

DROP TABLE _capture_semantic_ir_footprint_call_target_obligations;

INSERT INTO candidate_macro_semantic_ir_call_control_obligations SELECT * FROM _capture_candidate_macro_semantic_ir_call_control_obligations;

DROP TABLE _capture_candidate_macro_semantic_ir_call_control_obligations;

INSERT INTO candidate_macro_semantic_ir_footprint_call_target_obligations SELECT * FROM _capture_candidate_macro_semantic_ir_footprint_call_target_obligations;

DROP TABLE _capture_candidate_macro_semantic_ir_footprint_call_target_obligations;
