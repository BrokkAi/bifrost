-- Migration 0421 (#12128): Rust async body execution and generic memory interference.

-- Compatibility class: reader-breaking, fenced by user_version.

-- Preserve children explicitly with foreign keys ON as well as OFF.

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_events" AS SELECT * FROM "candidate_macro_semantic_ir_events";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_procedures" AS SELECT * FROM "candidate_macro_semantic_ir_procedures";

CREATE TEMP TABLE "_async_body_semantic_ir_events" AS SELECT * FROM "semantic_ir_events";

CREATE TEMP TABLE "_async_body_semantic_ir_procedures" AS SELECT * FROM "semantic_ir_procedures";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_call_control_coverage" AS SELECT * FROM "candidate_macro_semantic_ir_call_control_coverage";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_candidates" AS SELECT * FROM "candidate_macro_semantic_ir_candidates";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_nodes" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_nodes";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_projections" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_projections";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_footprint_coverage" AS SELECT * FROM "candidate_macro_semantic_ir_footprint_coverage";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_result_type_classes" AS SELECT * FROM "candidate_macro_semantic_ir_result_type_classes";

CREATE TEMP TABLE "_async_body_semantic_ir_call_control_coverage" AS SELECT * FROM "semantic_ir_call_control_coverage";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_nodes" AS SELECT * FROM "semantic_ir_cleanup_nodes";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_projections" AS SELECT * FROM "semantic_ir_cleanup_projections";

CREATE TEMP TABLE "_async_body_semantic_ir_footprint_coverage" AS SELECT * FROM "semantic_ir_footprint_coverage";

CREATE TEMP TABLE "_async_body_semantic_ir_result_type_classes" AS SELECT * FROM "semantic_ir_result_type_classes";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_call_control_classes" AS SELECT * FROM "candidate_macro_semantic_ir_call_control_classes";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_actions" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_actions";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_anchors" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_anchors";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_owners" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_owners";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_footprint_coverage_classes" AS SELECT * FROM "candidate_macro_semantic_ir_footprint_coverage_classes";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_gaps" AS SELECT * FROM "candidate_macro_semantic_ir_gaps";

CREATE TEMP TABLE "_async_body_semantic_ir_call_control_classes" AS SELECT * FROM "semantic_ir_call_control_classes";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_actions" AS SELECT * FROM "semantic_ir_cleanup_actions";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_anchors" AS SELECT * FROM "semantic_ir_cleanup_anchors";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_owners" AS SELECT * FROM "semantic_ir_cleanup_owners";

CREATE TEMP TABLE "_async_body_semantic_ir_footprint_coverage_classes" AS SELECT * FROM "semantic_ir_footprint_coverage_classes";

CREATE TEMP TABLE "_async_body_semantic_ir_gaps" AS SELECT * FROM "semantic_ir_gaps";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_call_control_obligations" AS SELECT * FROM "candidate_macro_semantic_ir_call_control_obligations";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_projection_members" AS SELECT * FROM "candidate_macro_semantic_ir_cleanup_projection_members";

CREATE TEMP TABLE "_async_body_candidate_macro_semantic_ir_footprint_call_target_obligations" AS SELECT * FROM "candidate_macro_semantic_ir_footprint_call_target_obligations";

CREATE TEMP TABLE "_async_body_semantic_ir_call_control_obligations" AS SELECT * FROM "semantic_ir_call_control_obligations";

CREATE TEMP TABLE "_async_body_semantic_ir_cleanup_projection_members" AS SELECT * FROM "semantic_ir_cleanup_projection_members";

CREATE TEMP TABLE "_async_body_semantic_ir_footprint_call_target_obligations" AS SELECT * FROM "semantic_ir_footprint_call_target_obligations";

DELETE FROM "semantic_ir_footprint_call_target_obligations";

DELETE FROM "semantic_ir_cleanup_projection_members";

DELETE FROM "semantic_ir_call_control_obligations";

DELETE FROM "candidate_macro_semantic_ir_footprint_call_target_obligations";

DELETE FROM "candidate_macro_semantic_ir_cleanup_projection_members";

DELETE FROM "candidate_macro_semantic_ir_call_control_obligations";

DELETE FROM "semantic_ir_gaps";

DELETE FROM "semantic_ir_footprint_coverage_classes";

DELETE FROM "semantic_ir_cleanup_owners";

DELETE FROM "semantic_ir_cleanup_anchors";

DELETE FROM "semantic_ir_cleanup_actions";

DELETE FROM "semantic_ir_call_control_classes";

DELETE FROM "candidate_macro_semantic_ir_gaps";

DELETE FROM "candidate_macro_semantic_ir_footprint_coverage_classes";

DELETE FROM "candidate_macro_semantic_ir_cleanup_owners";

DELETE FROM "candidate_macro_semantic_ir_cleanup_anchors";

DELETE FROM "candidate_macro_semantic_ir_cleanup_actions";

DELETE FROM "candidate_macro_semantic_ir_call_control_classes";

DELETE FROM "semantic_ir_result_type_classes";

DELETE FROM "semantic_ir_footprint_coverage";

DELETE FROM "semantic_ir_cleanup_projections";

DELETE FROM "semantic_ir_cleanup_nodes";

DELETE FROM "semantic_ir_call_control_coverage";

DELETE FROM "candidate_macro_semantic_ir_result_type_classes";

DELETE FROM "candidate_macro_semantic_ir_footprint_coverage";

DELETE FROM "candidate_macro_semantic_ir_cleanup_projections";

DELETE FROM "candidate_macro_semantic_ir_cleanup_nodes";

DELETE FROM "candidate_macro_semantic_ir_candidates";

DELETE FROM "candidate_macro_semantic_ir_call_control_coverage";

DELETE FROM "semantic_ir_procedures";

DELETE FROM "semantic_ir_events";

DELETE FROM "candidate_macro_semantic_ir_procedures";

DELETE FROM "candidate_macro_semantic_ir_events";

DROP TABLE "candidate_macro_semantic_ir_events";

CREATE TABLE candidate_macro_semantic_ir_events(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  effect        INTEGER NOT NULL CHECK(effect BETWEEN 0 AND 21),
  sub_kind      INTEGER,
  value_a       INTEGER,
  value_b       INTEGER,
  value_c       INTEGER,
  location      INTEGER,
  allocation    INTEGER,
  call_site     INTEGER,
  capture       INTEGER,
  gap           INTEGER,
  locator       INTEGER,
  suspend_point INTEGER,
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE "candidate_macro_semantic_ir_gaps";

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
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 15),
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

DROP TABLE "candidate_macro_semantic_ir_procedures";

CREATE TABLE candidate_macro_semantic_ir_procedures(
  blob_id                INTEGER NOT NULL,
  procedure              INTEGER NOT NULL,
  locator                INTEGER NOT NULL,
  lexical_parent         INTEGER,
  kind                   INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 8),
  is_async               INTEGER NOT NULL CHECK(is_async IN (0, 1)),
  is_generator           INTEGER NOT NULL CHECK(is_generator IN (0, 1)),
  is_static              INTEGER NOT NULL CHECK(is_static IN (0, 1)),
  is_synthetic           INTEGER NOT NULL CHECK(is_synthetic IN (0, 1)),
  invocation             INTEGER NOT NULL CHECK(invocation BETWEEN 0 AND 2),
  dispatch_extensibility INTEGER NOT NULL CHECK(dispatch_extensibility BETWEEN 0 AND 1),
  call_boundary          INTEGER NOT NULL CHECK(call_boundary BETWEEN 0 AND 1),
  receiver_binding       INTEGER NOT NULL CHECK(receiver_binding BETWEEN 0 AND 1),
  construction_return    INTEGER NOT NULL CHECK(construction_return BETWEEN 0 AND 1),
  source                 INTEGER NOT NULL,
  evidence               INTEGER NOT NULL, has_declared_results INTEGER NOT NULL DEFAULT 0 CHECK(has_declared_results IN (0, 1)),
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE "semantic_ir_events";

CREATE TABLE semantic_ir_events(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  effect        INTEGER NOT NULL CHECK(effect BETWEEN 0 AND 21),
  sub_kind      INTEGER,
  value_a       INTEGER,
  value_b       INTEGER,
  value_c       INTEGER,
  location      INTEGER,
  allocation    INTEGER,
  call_site     INTEGER,
  capture       INTEGER,
  gap           INTEGER,
  locator       INTEGER,
  suspend_point INTEGER,
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE "semantic_ir_gaps";

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
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 15),
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

DROP TABLE "semantic_ir_procedures";

CREATE TABLE semantic_ir_procedures(
  blob_id                INTEGER NOT NULL,
  procedure              INTEGER NOT NULL,
  locator                INTEGER NOT NULL,
  lexical_parent         INTEGER,
  kind                   INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 8),
  is_async               INTEGER NOT NULL CHECK(is_async IN (0, 1)),
  is_generator           INTEGER NOT NULL CHECK(is_generator IN (0, 1)),
  is_static              INTEGER NOT NULL CHECK(is_static IN (0, 1)),
  is_synthetic           INTEGER NOT NULL CHECK(is_synthetic IN (0, 1)),
  invocation             INTEGER NOT NULL CHECK(invocation BETWEEN 0 AND 2),
  dispatch_extensibility INTEGER NOT NULL CHECK(dispatch_extensibility BETWEEN 0 AND 1),
  call_boundary          INTEGER NOT NULL CHECK(call_boundary BETWEEN 0 AND 1),
  receiver_binding       INTEGER NOT NULL CHECK(receiver_binding BETWEEN 0 AND 1),
  construction_return    INTEGER NOT NULL CHECK(construction_return BETWEEN 0 AND 1),
  source                 INTEGER NOT NULL,
  evidence               INTEGER NOT NULL, has_declared_results INTEGER NOT NULL DEFAULT 0 CHECK(has_declared_results IN (0, 1)),
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO "candidate_macro_semantic_ir_events" SELECT * FROM "_async_body_candidate_macro_semantic_ir_events";

DROP TABLE "_async_body_candidate_macro_semantic_ir_events";

INSERT INTO "candidate_macro_semantic_ir_procedures" SELECT * FROM "_async_body_candidate_macro_semantic_ir_procedures";

DROP TABLE "_async_body_candidate_macro_semantic_ir_procedures";

INSERT INTO "semantic_ir_events" SELECT * FROM "_async_body_semantic_ir_events";

DROP TABLE "_async_body_semantic_ir_events";

INSERT INTO "semantic_ir_procedures" SELECT * FROM "_async_body_semantic_ir_procedures";

DROP TABLE "_async_body_semantic_ir_procedures";

INSERT INTO "candidate_macro_semantic_ir_call_control_coverage" SELECT * FROM "_async_body_candidate_macro_semantic_ir_call_control_coverage";

DROP TABLE "_async_body_candidate_macro_semantic_ir_call_control_coverage";

INSERT INTO "candidate_macro_semantic_ir_candidates" SELECT * FROM "_async_body_candidate_macro_semantic_ir_candidates";

DROP TABLE "_async_body_candidate_macro_semantic_ir_candidates";

INSERT INTO "candidate_macro_semantic_ir_cleanup_nodes" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_nodes";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_nodes";

INSERT INTO "candidate_macro_semantic_ir_cleanup_projections" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_projections";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_projections";

INSERT INTO "candidate_macro_semantic_ir_footprint_coverage" SELECT * FROM "_async_body_candidate_macro_semantic_ir_footprint_coverage";

DROP TABLE "_async_body_candidate_macro_semantic_ir_footprint_coverage";

INSERT INTO "candidate_macro_semantic_ir_result_type_classes" SELECT * FROM "_async_body_candidate_macro_semantic_ir_result_type_classes";

DROP TABLE "_async_body_candidate_macro_semantic_ir_result_type_classes";

INSERT INTO "semantic_ir_call_control_coverage" SELECT * FROM "_async_body_semantic_ir_call_control_coverage";

DROP TABLE "_async_body_semantic_ir_call_control_coverage";

INSERT INTO "semantic_ir_cleanup_nodes" SELECT * FROM "_async_body_semantic_ir_cleanup_nodes";

DROP TABLE "_async_body_semantic_ir_cleanup_nodes";

INSERT INTO "semantic_ir_cleanup_projections" SELECT * FROM "_async_body_semantic_ir_cleanup_projections";

DROP TABLE "_async_body_semantic_ir_cleanup_projections";

INSERT INTO "semantic_ir_footprint_coverage" SELECT * FROM "_async_body_semantic_ir_footprint_coverage";

DROP TABLE "_async_body_semantic_ir_footprint_coverage";

INSERT INTO "semantic_ir_result_type_classes" SELECT * FROM "_async_body_semantic_ir_result_type_classes";

DROP TABLE "_async_body_semantic_ir_result_type_classes";

INSERT INTO "candidate_macro_semantic_ir_call_control_classes" SELECT * FROM "_async_body_candidate_macro_semantic_ir_call_control_classes";

DROP TABLE "_async_body_candidate_macro_semantic_ir_call_control_classes";

INSERT INTO "candidate_macro_semantic_ir_cleanup_actions" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_actions";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_actions";

INSERT INTO "candidate_macro_semantic_ir_cleanup_anchors" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_anchors";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_anchors";

INSERT INTO "candidate_macro_semantic_ir_cleanup_owners" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_owners";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_owners";

INSERT INTO "candidate_macro_semantic_ir_footprint_coverage_classes" SELECT * FROM "_async_body_candidate_macro_semantic_ir_footprint_coverage_classes";

DROP TABLE "_async_body_candidate_macro_semantic_ir_footprint_coverage_classes";

INSERT INTO "candidate_macro_semantic_ir_gaps" SELECT * FROM "_async_body_candidate_macro_semantic_ir_gaps";

DROP TABLE "_async_body_candidate_macro_semantic_ir_gaps";

INSERT INTO "semantic_ir_call_control_classes" SELECT * FROM "_async_body_semantic_ir_call_control_classes";

DROP TABLE "_async_body_semantic_ir_call_control_classes";

INSERT INTO "semantic_ir_cleanup_actions" SELECT * FROM "_async_body_semantic_ir_cleanup_actions";

DROP TABLE "_async_body_semantic_ir_cleanup_actions";

INSERT INTO "semantic_ir_cleanup_anchors" SELECT * FROM "_async_body_semantic_ir_cleanup_anchors";

DROP TABLE "_async_body_semantic_ir_cleanup_anchors";

INSERT INTO "semantic_ir_cleanup_owners" SELECT * FROM "_async_body_semantic_ir_cleanup_owners";

DROP TABLE "_async_body_semantic_ir_cleanup_owners";

INSERT INTO "semantic_ir_footprint_coverage_classes" SELECT * FROM "_async_body_semantic_ir_footprint_coverage_classes";

DROP TABLE "_async_body_semantic_ir_footprint_coverage_classes";

INSERT INTO "semantic_ir_gaps" SELECT * FROM "_async_body_semantic_ir_gaps";

DROP TABLE "_async_body_semantic_ir_gaps";

INSERT INTO "candidate_macro_semantic_ir_call_control_obligations" SELECT * FROM "_async_body_candidate_macro_semantic_ir_call_control_obligations";

DROP TABLE "_async_body_candidate_macro_semantic_ir_call_control_obligations";

INSERT INTO "candidate_macro_semantic_ir_cleanup_projection_members" SELECT * FROM "_async_body_candidate_macro_semantic_ir_cleanup_projection_members";

DROP TABLE "_async_body_candidate_macro_semantic_ir_cleanup_projection_members";

INSERT INTO "candidate_macro_semantic_ir_footprint_call_target_obligations" SELECT * FROM "_async_body_candidate_macro_semantic_ir_footprint_call_target_obligations";

DROP TABLE "_async_body_candidate_macro_semantic_ir_footprint_call_target_obligations";

INSERT INTO "semantic_ir_call_control_obligations" SELECT * FROM "_async_body_semantic_ir_call_control_obligations";

DROP TABLE "_async_body_semantic_ir_call_control_obligations";

INSERT INTO "semantic_ir_cleanup_projection_members" SELECT * FROM "_async_body_semantic_ir_cleanup_projection_members";

DROP TABLE "_async_body_semantic_ir_cleanup_projection_members";

INSERT INTO "semantic_ir_footprint_call_target_obligations" SELECT * FROM "_async_body_semantic_ir_footprint_call_target_obligations";

DROP TABLE "_async_body_semantic_ir_footprint_call_target_obligations";
