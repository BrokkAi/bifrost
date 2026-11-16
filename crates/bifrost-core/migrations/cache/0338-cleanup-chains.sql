-- #11360 M1: immutable procedure-local cleanup chains.
-- Readers walk parent links and node-ordered actions/owners, then select anchors
-- by source point or head. No route-times-owner rows are stored.
-- id is incidental SQL row identity. Every cross-row reference uses dense
-- procedure-local arena IDs (node, anchor, projection and action ordinal).
-- NULL parent/head/stop denotes the empty sentinel. Parent-before-child and
-- dense ordinals are validated at publication/hydration (SQL checks nonnegative
-- ordinals and unique positions; it cannot check a complete arena while loading).
-- Typed places, destructor resolutions/target lists, source mappings, evidence
-- and incomplete reasons use the existing semantic_ir_* integer codecs.
-- region is the procedure builder's cleanup-region ID, not a source-text name.
-- Owner lifecycle: None=0, ScopeEnd=1. Anchor purpose: Completion=0, LifetimeEnd=1, Exit=2.
-- Ancestor-stop validity is checked by the shared arena validator.

CREATE TABLE semantic_ir_cleanup_nodes(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL CHECK(node >= 0),
  parent INTEGER,
  region INTEGER CHECK(region IS NULL OR region >= 0),
  UNIQUE(blob_id, procedure, node),
  UNIQUE(blob_id, procedure, id),
  CHECK(parent IS NULL OR parent < node),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_procedures(blob_id, procedure),
  FOREIGN KEY(blob_id, procedure, parent) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node)
) STRICT;

CREATE TABLE semantic_ir_cleanup_actions(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  place_kind INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator INTEGER,
  place_location INTEGER,
  behavior INTEGER CHECK(behavior BETWEEN 0 AND 1),
  destructor_resolution INTEGER CHECK(destructor_resolution BETWEEN 0 AND 5),
  destructor_targets INTEGER,
  source INTEGER NOT NULL,
  evidence INTEGER NOT NULL,
  reason_domain INTEGER CHECK(reason_domain BETWEEN 0 AND 1),
  reason INTEGER CHECK(reason BETWEEN 0 AND 9),
  -- Incomplete evidence can differ from the cleanup action evidence.
  incomplete_evidence INTEGER,
  CHECK((place_kind = 0 AND place_locator IS NOT NULL AND place_location IS NULL) OR
        (place_kind = 1 AND place_locator IS NULL AND place_location IS NOT NULL)),
  CHECK((kind = 0) = (behavior IS NOT NULL)),
  CHECK((behavior IS 1) = (destructor_resolution IS NOT NULL)),
  CHECK(destructor_resolution IS NOT NULL OR destructor_targets IS NULL),
  CHECK((reason_domain IS NULL) = (reason IS NULL)),
  CHECK(reason_domain IS NULL OR reason_domain = 0),
  CHECK((reason IS NULL) = (incomplete_evidence IS NULL)),
  UNIQUE(blob_id, procedure, node, ordinal),
  UNIQUE(blob_id, procedure, id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, node) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, incomplete_evidence) REFERENCES semantic_ir_evidence(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id, procedure, source) REFERENCES semantic_ir_source_mappings(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id, procedure, evidence) REFERENCES semantic_ir_evidence(blob_id, procedure, evidence)
) STRICT;

CREATE TABLE semantic_ir_cleanup_owners(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  value INTEGER NOT NULL,
  -- Typed owner storage place; identical to cleanup action places.
  place_kind INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator INTEGER,
  place_location INTEGER,
  lifecycle INTEGER NOT NULL CHECK(lifecycle BETWEEN 0 AND 1),
  -- Optional invalidation target, cause and strength form one atomic payload.
  target_kind INTEGER CHECK(target_kind BETWEEN 0 AND 1),
  target_value INTEGER,
  target_origin INTEGER,
  invalidation_cause INTEGER CHECK(invalidation_cause BETWEEN 0 AND 3),
  invalidation_strength INTEGER CHECK(invalidation_strength BETWEEN 0 AND 1),
  source INTEGER NOT NULL,
  evidence INTEGER NOT NULL,
  CHECK((place_kind = 0 AND place_locator IS NOT NULL AND place_location IS NULL) OR
        (place_kind = 1 AND place_locator IS NULL AND place_location IS NOT NULL)),
  CHECK((target_kind IS NULL AND target_value IS NULL AND target_origin IS NULL AND
         invalidation_cause IS NULL AND invalidation_strength IS NULL) OR
        (target_kind IS NOT NULL AND invalidation_cause IS NOT NULL AND invalidation_strength IS NOT NULL AND
         ((target_kind = 0 AND target_value IS NOT NULL AND target_origin IS NULL) OR
          (target_kind = 1 AND target_value IS NULL AND target_origin IS NOT NULL)))),
  UNIQUE(blob_id, procedure, node, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, node) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, source) REFERENCES semantic_ir_source_mappings(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id, procedure, evidence) REFERENCES semantic_ir_evidence(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id, procedure, target_value) REFERENCES semantic_ir_values(blob_id, procedure, value),
  FOREIGN KEY(blob_id, procedure, target_origin) REFERENCES semantic_ir_pointer_origins(blob_id, procedure, origin),
  FOREIGN KEY(blob_id, procedure, value) REFERENCES semantic_ir_values(blob_id, procedure, value)
) STRICT;

-- Canonical procedure-local selections, including empty selections.
CREATE TABLE semantic_ir_cleanup_projections(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  projection INTEGER NOT NULL CHECK(projection >= 0),
  UNIQUE(blob_id, procedure, projection),
  UNIQUE(blob_id, procedure, id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_procedures(blob_id, procedure)
) STRICT;

-- Dense ordered selected-action cursors; equal lists share a projection row.
CREATE TABLE semantic_ir_cleanup_projection_members(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  projection INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  node INTEGER NOT NULL,
  action_ordinal INTEGER NOT NULL CHECK(action_ordinal >= 0),
  PRIMARY KEY(blob_id, procedure, projection, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, projection) REFERENCES semantic_ir_cleanup_projections(blob_id, procedure, projection),
  FOREIGN KEY(blob_id, procedure, node, action_ordinal) REFERENCES semantic_ir_cleanup_actions(blob_id, procedure, node, ordinal)
) STRICT;

CREATE TABLE semantic_ir_cleanup_anchors(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  anchor INTEGER NOT NULL CHECK(anchor >= 0),
  point INTEGER NOT NULL,
  head INTEGER,
  stop INTEGER,
  destination INTEGER NOT NULL,
  destination_kind INTEGER NOT NULL CHECK(destination_kind BETWEEN 0 AND 5),
  edge_kind INTEGER NOT NULL CHECK(edge_kind BETWEEN 0 AND 8),
  -- Direct fact insertion offsets preserve logical publication ordering.
  drop_offset INTEGER NOT NULL CHECK(drop_offset >= 0),
  scope_end_offset INTEGER NOT NULL CHECK(scope_end_offset >= 0),
  incomplete_offset INTEGER NOT NULL CHECK(incomplete_offset >= 0),
  pointer_invalidation_offset INTEGER NOT NULL CHECK(pointer_invalidation_offset >= 0),
  -- NULL selects every action in the segment; otherwise selects interned cursors.
  projection INTEGER,
  purpose INTEGER NOT NULL CHECK(purpose BETWEEN 0 AND 2),
  UNIQUE(blob_id, procedure, anchor),
  UNIQUE(blob_id, procedure, id),
  CHECK(head IS NOT NULL OR stop IS NULL),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, projection) REFERENCES semantic_ir_cleanup_projections(blob_id, procedure, projection),
  FOREIGN KEY(blob_id, procedure, point) REFERENCES semantic_ir_points(blob_id, procedure, point),
  FOREIGN KEY(blob_id, procedure, destination) REFERENCES semantic_ir_points(blob_id, procedure, point),
  FOREIGN KEY(blob_id, procedure, head) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, stop) REFERENCES semantic_ir_cleanup_nodes(blob_id, procedure, node)
) STRICT;
-- Anchor readers select the segments affecting a point, or referencing a head.
CREATE INDEX semantic_ir_cleanup_anchors_by_point
  ON semantic_ir_cleanup_anchors(blob_id, procedure, point, anchor);
CREATE INDEX semantic_ir_cleanup_anchors_by_head
  ON semantic_ir_cleanup_anchors(blob_id, procedure, head, anchor);

CREATE TABLE candidate_macro_semantic_ir_cleanup_nodes(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL CHECK(node >= 0),
  parent INTEGER,
  region INTEGER CHECK(region IS NULL OR region >= 0),
  UNIQUE(blob_id, procedure, node),
  UNIQUE(blob_id, procedure, id),
  CHECK(parent IS NULL OR parent < node),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure),
  FOREIGN KEY(blob_id, procedure, parent) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node)
) STRICT;

CREATE TABLE candidate_macro_semantic_ir_cleanup_actions(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  place_kind INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator INTEGER,
  place_location INTEGER,
  behavior INTEGER CHECK(behavior BETWEEN 0 AND 1),
  destructor_resolution INTEGER CHECK(destructor_resolution BETWEEN 0 AND 5),
  destructor_targets INTEGER,
  source INTEGER NOT NULL,
  evidence INTEGER NOT NULL,
  reason_domain INTEGER CHECK(reason_domain BETWEEN 0 AND 1),
  reason INTEGER CHECK(reason BETWEEN 0 AND 9),
  -- Incomplete evidence can differ from the cleanup action evidence.
  incomplete_evidence INTEGER,
  CHECK((place_kind = 0 AND place_locator IS NOT NULL AND place_location IS NULL) OR
        (place_kind = 1 AND place_locator IS NULL AND place_location IS NOT NULL)),
  CHECK((kind = 0) = (behavior IS NOT NULL)),
  CHECK((behavior IS 1) = (destructor_resolution IS NOT NULL)),
  CHECK(destructor_resolution IS NOT NULL OR destructor_targets IS NULL),
  CHECK((reason_domain IS NULL) = (reason IS NULL)),
  CHECK(reason_domain IS NULL OR reason_domain = 0),
  CHECK((reason IS NULL) = (incomplete_evidence IS NULL)),
  UNIQUE(blob_id, procedure, node, ordinal),
  UNIQUE(blob_id, procedure, id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, node) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, incomplete_evidence) REFERENCES candidate_macro_semantic_ir_evidence(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id, procedure, source) REFERENCES candidate_macro_semantic_ir_source_mappings(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id, procedure, evidence) REFERENCES candidate_macro_semantic_ir_evidence(blob_id, procedure, evidence)
) STRICT;

CREATE TABLE candidate_macro_semantic_ir_cleanup_owners(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  node INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  value INTEGER NOT NULL,
  -- Typed owner storage place; identical to cleanup action places.
  place_kind INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator INTEGER,
  place_location INTEGER,
  lifecycle INTEGER NOT NULL CHECK(lifecycle BETWEEN 0 AND 1),
  -- Optional invalidation target, cause and strength form one atomic payload.
  target_kind INTEGER CHECK(target_kind BETWEEN 0 AND 1),
  target_value INTEGER,
  target_origin INTEGER,
  invalidation_cause INTEGER CHECK(invalidation_cause BETWEEN 0 AND 3),
  invalidation_strength INTEGER CHECK(invalidation_strength BETWEEN 0 AND 1),
  source INTEGER NOT NULL,
  evidence INTEGER NOT NULL,
  CHECK((place_kind = 0 AND place_locator IS NOT NULL AND place_location IS NULL) OR
        (place_kind = 1 AND place_locator IS NULL AND place_location IS NOT NULL)),
  CHECK((target_kind IS NULL AND target_value IS NULL AND target_origin IS NULL AND
         invalidation_cause IS NULL AND invalidation_strength IS NULL) OR
        (target_kind IS NOT NULL AND invalidation_cause IS NOT NULL AND invalidation_strength IS NOT NULL AND
         ((target_kind = 0 AND target_value IS NOT NULL AND target_origin IS NULL) OR
          (target_kind = 1 AND target_value IS NULL AND target_origin IS NOT NULL)))),
  UNIQUE(blob_id, procedure, node, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, node) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, source) REFERENCES candidate_macro_semantic_ir_source_mappings(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id, procedure, evidence) REFERENCES candidate_macro_semantic_ir_evidence(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id, procedure, target_value) REFERENCES candidate_macro_semantic_ir_values(blob_id, procedure, value),
  FOREIGN KEY(blob_id, procedure, target_origin) REFERENCES candidate_macro_semantic_ir_pointer_origins(blob_id, procedure, origin),
  FOREIGN KEY(blob_id, procedure, value) REFERENCES candidate_macro_semantic_ir_values(blob_id, procedure, value)
) STRICT;

-- Canonical procedure-local selections, including empty selections.
CREATE TABLE candidate_macro_semantic_ir_cleanup_projections(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  projection INTEGER NOT NULL CHECK(projection >= 0),
  UNIQUE(blob_id, procedure, projection),
  UNIQUE(blob_id, procedure, id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure)
) STRICT;

-- Dense ordered selected-action cursors; equal lists share a projection row.
CREATE TABLE candidate_macro_semantic_ir_cleanup_projection_members(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  projection INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  node INTEGER NOT NULL,
  action_ordinal INTEGER NOT NULL CHECK(action_ordinal >= 0),
  PRIMARY KEY(blob_id, procedure, projection, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, projection) REFERENCES candidate_macro_semantic_ir_cleanup_projections(blob_id, procedure, projection),
  FOREIGN KEY(blob_id, procedure, node, action_ordinal) REFERENCES candidate_macro_semantic_ir_cleanup_actions(blob_id, procedure, node, ordinal)
) STRICT;

CREATE TABLE candidate_macro_semantic_ir_cleanup_anchors(
  id INTEGER PRIMARY KEY,
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  anchor INTEGER NOT NULL CHECK(anchor >= 0),
  point INTEGER NOT NULL,
  head INTEGER,
  stop INTEGER,
  destination INTEGER NOT NULL,
  destination_kind INTEGER NOT NULL CHECK(destination_kind BETWEEN 0 AND 5),
  edge_kind INTEGER NOT NULL CHECK(edge_kind BETWEEN 0 AND 8),
  -- Direct fact insertion offsets preserve logical publication ordering.
  drop_offset INTEGER NOT NULL CHECK(drop_offset >= 0),
  scope_end_offset INTEGER NOT NULL CHECK(scope_end_offset >= 0),
  incomplete_offset INTEGER NOT NULL CHECK(incomplete_offset >= 0),
  pointer_invalidation_offset INTEGER NOT NULL CHECK(pointer_invalidation_offset >= 0),
  -- NULL selects every action in the segment; otherwise selects interned cursors.
  projection INTEGER,
  purpose INTEGER NOT NULL CHECK(purpose BETWEEN 0 AND 2),
  UNIQUE(blob_id, procedure, anchor),
  UNIQUE(blob_id, procedure, id),
  CHECK(head IS NOT NULL OR stop IS NULL),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, projection) REFERENCES candidate_macro_semantic_ir_cleanup_projections(blob_id, procedure, projection),
  FOREIGN KEY(blob_id, procedure, point) REFERENCES candidate_macro_semantic_ir_points(blob_id, procedure, point),
  FOREIGN KEY(blob_id, procedure, destination) REFERENCES candidate_macro_semantic_ir_points(blob_id, procedure, point),
  FOREIGN KEY(blob_id, procedure, head) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node),
  FOREIGN KEY(blob_id, procedure, stop) REFERENCES candidate_macro_semantic_ir_cleanup_nodes(blob_id, procedure, node)
) STRICT;
-- Anchor readers select the segments affecting a point, or referencing a head.
CREATE INDEX candidate_macro_semantic_ir_cleanup_anchors_by_point
  ON candidate_macro_semantic_ir_cleanup_anchors(blob_id, procedure, point, anchor);
CREATE INDEX candidate_macro_semantic_ir_cleanup_anchors_by_head
  ON candidate_macro_semantic_ir_cleanup_anchors(blob_id, procedure, head, anchor);
