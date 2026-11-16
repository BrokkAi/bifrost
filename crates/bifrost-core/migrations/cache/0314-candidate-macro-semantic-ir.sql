-- Migration 0314: isolated candidate-macro semantic IR and partial flows.
-- Compatible: additive guarded relations; existing publication rows are unchanged.
-- Candidate macro alternatives use the base typed row encodings but are never
-- part of the ordinary decoder table registry. All rows belong to the base
-- publication and are collected with it. JSONB cells retain the shared codec.

CREATE TABLE candidate_macro_semantic_ir_allocations(
  blob_id    INTEGER NOT NULL,
  procedure  INTEGER NOT NULL,
  allocation INTEGER NOT NULL,
  point      INTEGER NOT NULL,
  result     INTEGER NOT NULL,
  kind       INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6),
  kind_text  INTEGER,
  source     INTEGER NOT NULL,
  evidence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, allocation),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_blocks(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  block     INTEGER NOT NULL,
  points    BLOB NOT NULL CHECK(json_valid(points, 8)),
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, block),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_call_arguments(
  blob_id     INTEGER NOT NULL,
  procedure   INTEGER NOT NULL,
  call_site   INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  value       INTEGER NOT NULL,
  expansion   INTEGER NOT NULL CHECK(expansion BETWEEN 0 AND 2),
  domain      INTEGER CHECK(domain BETWEEN 0 AND 3),
  domain_text INTEGER,
  keyword     INTEGER,
  PRIMARY KEY(blob_id, procedure, call_site, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_call_control_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  class INTEGER NOT NULL CHECK(class BETWEEN 1 AND 8),
  disposition INTEGER NOT NULL CHECK(disposition IN (1, 2, 3)),
  reason INTEGER,
  PRIMARY KEY(blob_id, procedure, class),
  CHECK((disposition = 1 AND reason IS NULL) OR
        (disposition = 2 AND reason BETWEEN 1 AND 3) OR
        (disposition = 3 AND reason BETWEEN 1 AND 5)),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_call_control_coverage(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_call_control_coverage(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  contract_version INTEGER NOT NULL CHECK(contract_version > 0),
  source_boundary INTEGER NOT NULL CHECK(source_boundary IN (1, 3)),
  source_reason INTEGER CHECK(source_reason BETWEEN 1 AND 5),
  admission INTEGER NOT NULL CHECK(admission IN (1, 3)),
  admission_reason INTEGER CHECK(admission_reason BETWEEN 1 AND 5),
  obligation_count INTEGER NOT NULL CHECK(obligation_count >= 0),
  PRIMARY KEY(blob_id, procedure),
  CHECK((source_boundary = 1 AND source_reason IS NULL) OR
        (source_boundary = 3 AND source_reason IS NOT NULL)),
  CHECK((admission = 1 AND admission_reason IS NULL) OR
        (admission = 3 AND admission_reason IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_call_control_obligations(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  call_site INTEGER NOT NULL,
  gap INTEGER NOT NULL,
  impacts INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  PRIMARY KEY(blob_id, procedure, call_site, gap),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_call_control_coverage(blob_id, procedure) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, call_site) REFERENCES candidate_macro_semantic_ir_call_sites(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id, procedure, gap) REFERENCES candidate_macro_semantic_ir_gaps(blob_id, procedure, gap)
) WITHOUT ROWID, STRICT;

CREATE TABLE "candidate_macro_semantic_ir_call_sites"(
  blob_id                  INTEGER NOT NULL,
  procedure                INTEGER NOT NULL,
  call_site                INTEGER NOT NULL,
  point                    INTEGER NOT NULL,
  invocation_mode          INTEGER NOT NULL CHECK(invocation_mode BETWEEN 0 AND 1),
  execution_timing         INTEGER NOT NULL CHECK(execution_timing BETWEEN 0 AND 9),
  callee                   INTEGER NOT NULL,
  receiver                 INTEGER,
  result                   INTEGER,
  thrown                   INTEGER,
  normal_results           BLOB CHECK(normal_results IS NULL OR json_valid(normal_results, 8)),
  target_resolution        INTEGER NOT NULL CHECK(target_resolution BETWEEN 0 AND 5),
  targets                  INTEGER,
  target_evidence          INTEGER NOT NULL,
  normal_continuation      INTEGER NOT NULL CHECK(normal_continuation BETWEEN 0 AND 5),
  normal_target            INTEGER,
  exceptional_continuation INTEGER NOT NULL CHECK(exceptional_continuation BETWEEN 0 AND 5),
  exceptional_target       INTEGER,
  source                   INTEGER NOT NULL,
  evidence                 INTEGER NOT NULL,
  member                   INTEGER,
  receiver_place_kind      INTEGER CHECK(receiver_place_kind BETWEEN 0 AND 1),
  receiver_place_locator   INTEGER,
  receiver_place_location  INTEGER,
  receiver_pointer_depth   INTEGER
    CHECK(receiver_pointer_depth BETWEEN 0 AND 4294967295),
  CHECK(member IS NULL OR receiver IS NOT NULL),
  CHECK((receiver_place_kind IS 0) = (receiver_place_locator IS NOT NULL)),
  CHECK((receiver_place_kind IS 1) = (receiver_place_location IS NOT NULL)),
  CHECK(member IS NOT NULL OR
        (receiver_place_kind IS NULL AND receiver_pointer_depth IS NULL)),
  CHECK(target_resolution NOT IN (2, 3) OR targets IS NULL),
  CHECK((normal_continuation = 0) = (normal_target IS NOT NULL)),
  CHECK((exceptional_continuation = 0) = (exceptional_target IS NOT NULL)),
  PRIMARY KEY(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, receiver_place_locator)
    REFERENCES candidate_macro_semantic_ir_locators(blob_id, locator) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, receiver_place_location)
    REFERENCES candidate_macro_semantic_ir_memory_locations(blob_id, procedure, location) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_callable_targets(
  blob_id           INTEGER NOT NULL,
  procedure         INTEGER NOT NULL,
  targets           INTEGER NOT NULL,
  ordinal           INTEGER NOT NULL,
  kind              INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 3),
  local_procedure   INTEGER,
  locator           INTEGER,
  artifact_identity BLOB CHECK(artifact_identity IS NULL OR json_valid(artifact_identity, 8)),
  PRIMARY KEY(blob_id, procedure, targets, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_captures(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  capture       INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  callable      INTEGER NOT NULL,
  target        INTEGER NOT NULL,
  environment   INTEGER NOT NULL,
  captured_kind INTEGER NOT NULL CHECK(captured_kind BETWEEN 0 AND 1),
  captured      INTEGER NOT NULL,
  destination   INTEGER NOT NULL,
  mode          INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 6),
  mode_text     INTEGER,
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, capture),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_control_edges(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  source_point INTEGER NOT NULL,
  target_point INTEGER NOT NULL,
  kind         INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 8),
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_declaration_segments(
  blob_id         INTEGER NOT NULL,
  declaration     INTEGER NOT NULL,
  ordinal         INTEGER NOT NULL,
  kind            INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 10),
  name            INTEGER,
  start_byte      INTEGER NOT NULL,
  start_line      INTEGER NOT NULL,
  start_column    INTEGER NOT NULL,
  end_byte        INTEGER NOT NULL,
  end_line        INTEGER NOT NULL,
  end_column      INTEGER NOT NULL,
  occurrence      INTEGER NOT NULL,
  sibling_ordinal INTEGER NOT NULL,
  PRIMARY KEY(blob_id, declaration, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_drops(
  blob_id               INTEGER NOT NULL,
  procedure             INTEGER NOT NULL,
  ordinal               INTEGER NOT NULL,
  place_kind            INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator         INTEGER,
  place_location        INTEGER,
  point                 INTEGER NOT NULL,
  behavior              INTEGER NOT NULL CHECK(behavior BETWEEN 0 AND 1),
  destructor_resolution INTEGER CHECK(destructor_resolution BETWEEN 0 AND 5),
  destructor_targets    INTEGER,
  source                INTEGER NOT NULL,
  evidence              INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_event_async_suspends(
  blob_id                  INTEGER NOT NULL,
  procedure                INTEGER NOT NULL,
  point                    INTEGER NOT NULL,
  ordinal                  INTEGER NOT NULL,
  normal_continuation      INTEGER NOT NULL CHECK(normal_continuation BETWEEN 0 AND 5),
  normal_target            INTEGER,
  exceptional_continuation INTEGER NOT NULL CHECK(exceptional_continuation BETWEEN 0 AND 5),
  exceptional_target       INTEGER,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_event_callables(
  blob_id           INTEGER NOT NULL,
  procedure         INTEGER NOT NULL,
  point             INTEGER NOT NULL,
  ordinal           INTEGER NOT NULL,
  target_resolution INTEGER NOT NULL CHECK(target_resolution BETWEEN 0 AND 5),
  targets           INTEGER,
  target_evidence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_event_offsets(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  offset_kind    INTEGER CHECK(offset_kind BETWEEN 0 AND 2),
  magnitude      TEXT,
  offset_value   INTEGER,
  negative       INTEGER CHECK(negative IN (0, 1)),
  allocation     INTEGER,
  return_ordinal INTEGER,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_event_synchronizations(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  payload_kind  INTEGER NOT NULL CHECK(payload_kind BETWEEN 0 AND 1),
  value         INTEGER NOT NULL,
  copy_kind     INTEGER CHECK(copy_kind BETWEEN 0 AND 2),
  copy_identity INTEGER CHECK(copy_identity BETWEEN 0 AND 1),
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_event_transfers(
  blob_id         INTEGER NOT NULL,
  procedure       INTEGER NOT NULL,
  point           INTEGER NOT NULL,
  ordinal         INTEGER NOT NULL,
  transfer_kind   INTEGER NOT NULL CHECK(transfer_kind BETWEEN 0 AND 5),
  transfer_detail INTEGER,
  operation       INTEGER NOT NULL CHECK(operation BETWEEN 0 AND 4),
  call_site       INTEGER,
  digest          BLOB CHECK(digest IS NULL OR length(digest) = 32),
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_events(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  effect        INTEGER NOT NULL CHECK(effect BETWEEN 0 AND 20),
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

CREATE TABLE candidate_macro_semantic_ir_evidence(
  blob_id             INTEGER NOT NULL,
  procedure           INTEGER NOT NULL,
  evidence            INTEGER NOT NULL,
  proof               INTEGER NOT NULL CHECK(proof BETWEEN 0 AND 1),
  proof_reason        INTEGER,
  completeness        INTEGER NOT NULL CHECK(completeness BETWEEN 0 AND 1),
  completeness_reason INTEGER,
  sources             BLOB NOT NULL CHECK(json_valid(sources, 8)),
  PRIMARY KEY(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_footprint_call_target_obligations(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  call_site INTEGER NOT NULL,
  gap INTEGER NOT NULL,
  impacts INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  PRIMARY KEY(blob_id, procedure, call_site, gap),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_footprint_coverage(blob_id, procedure) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, call_site) REFERENCES candidate_macro_semantic_ir_call_sites(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id, procedure, gap) REFERENCES candidate_macro_semantic_ir_gaps(blob_id, procedure, gap)
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_footprint_coverage(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  contract_version INTEGER NOT NULL CHECK(contract_version > 0),
  boundary_disposition INTEGER NOT NULL CHECK(boundary_disposition IN (1, 3)),
  boundary_reason INTEGER CHECK(boundary_reason IN (1, 2, 3, 4, 5)),
  PRIMARY KEY(blob_id, procedure),
  CHECK((boundary_disposition = 1 AND boundary_reason IS NULL) OR
        (boundary_disposition = 3 AND boundary_reason IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_footprint_coverage_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  class INTEGER NOT NULL CHECK(class BETWEEN 1 AND 15),
  disposition INTEGER NOT NULL CHECK(disposition IN (1, 2, 3)),
  reason INTEGER,
  PRIMARY KEY(blob_id, procedure, class),
  CHECK((disposition = 1 AND reason IS NULL) OR
        (disposition = 2 AND reason IN (1, 2)) OR
        (disposition = 3 AND reason IN (1, 2, 3, 4, 5))),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_footprint_coverage(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE "candidate_macro_semantic_ir_gaps"(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  gap              INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  subject          INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 7),
  subject_a        INTEGER,
  subject_b        INTEGER,
  capability       INTEGER NOT NULL CHECK(capability BETWEEN 0 AND 33),
  impacts          INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  budget_dimension INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit     INTEGER,
  budget_attempted INTEGER,
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 13),
  detail           INTEGER NOT NULL,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, gap),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_guard_facts(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  guard        INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  subject      INTEGER,
  predicate    INTEGER NOT NULL CHECK(predicate BETWEEN 0 AND 10),
  flag         INTEGER CHECK(flag IN (0, 1)),
  relation     INTEGER CHECK(relation BETWEEN 0 AND 3),
  constant     INTEGER,
  operand_a    INTEGER,
  operand_b    INTEGER,
  digest       INTEGER,
  true_target  INTEGER,
  true_kind    INTEGER,
  false_target INTEGER,
  false_kind   INTEGER,
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, guard),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_guarded_pattern_projections(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  whole_value    INTEGER NOT NULL,
  binder         INTEGER NOT NULL,
  pattern_source INTEGER NOT NULL,
  binder_source  INTEGER NOT NULL,
  path_len       INTEGER NOT NULL CHECK(path_len BETWEEN 1 AND 16),
  status         INTEGER NOT NULL CHECK(status = 0),
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_guarded_pattern_steps(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  candidate     INTEGER NOT NULL,
  step          INTEGER NOT NULL,
  kind          INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  tuple_ordinal INTEGER,
  named_text    INTEGER,
  CHECK((kind = 0 AND tuple_ordinal IS NOT NULL AND named_text IS NULL) OR
        (kind = 1 AND tuple_ordinal IS NULL AND named_text IS NOT NULL)),
  PRIMARY KEY(blob_id, procedure, candidate, step),
  FOREIGN KEY(blob_id, procedure, candidate)
    REFERENCES candidate_macro_semantic_ir_guarded_pattern_projections(blob_id, procedure, ordinal)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_incomplete_facts(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  subject        INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 3),
  place_kind     INTEGER,
  place_locator  INTEGER,
  place_location INTEGER,
  value          INTEGER,
  origin         INTEGER,
  reason_domain  INTEGER NOT NULL CHECK(reason_domain BETWEEN 0 AND 1),
  reason         INTEGER NOT NULL CHECK(reason BETWEEN 0 AND 9),
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_locators(
  blob_id      INTEGER NOT NULL,
  locator      INTEGER NOT NULL,
  path         INTEGER,
  declaration  INTEGER NOT NULL,
  role         INTEGER NOT NULL CHECK(role BETWEEN 0 AND 11),
  start_byte   INTEGER NOT NULL,
  start_line   INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_byte     INTEGER NOT NULL,
  end_line     INTEGER NOT NULL,
  end_column   INTEGER NOT NULL,
  occurrence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, locator),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_loop_sites(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal   INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  header    INTEGER NOT NULL,
  body      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_memory_locations(
  blob_id             INTEGER NOT NULL,
  procedure           INTEGER NOT NULL,
  location            INTEGER NOT NULL,
  kind                INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6),
  base                INTEGER,
  member              INTEGER,
  property_key        INTEGER,
  index_value         INTEGER,
  constant_index      TEXT,
  index_identity      INTEGER CHECK(index_identity BETWEEN 0 AND 1),
  lexical_parent      INTEGER,
  binding             INTEGER,
  value_copy          INTEGER NOT NULL CHECK(value_copy BETWEEN 0 AND 3),
  value_copy_identity INTEGER CHECK(value_copy_identity BETWEEN 0 AND 1),
  source              INTEGER NOT NULL,
  evidence            INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, location),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_move_outs(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  place_kind     INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator  INTEGER,
  place_location INTEGER,
  point          INTEGER NOT NULL,
  source_value   INTEGER NOT NULL,
  target_value   INTEGER NOT NULL,
  state_after    INTEGER NOT NULL CHECK(state_after BETWEEN 0 AND 2),
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_partial_flow_heads(
  blob_id         INTEGER NOT NULL,
  procedure       INTEGER NOT NULL,
  outcome         INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 3),
  detail          INTEGER,
  open            INTEGER NOT NULL CHECK(open IN (0, 1)),
  port_count      INTEGER NOT NULL CHECK(port_count >= 0),
  flow_count      INTEGER NOT NULL CHECK(flow_count >= 0),
  discharged_gaps BLOB NOT NULL CHECK(json_valid(discharged_gaps, 8)), relations_complete INTEGER NOT NULL DEFAULT 0 CHECK(relations_complete IN (0, 1)),
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_partial_flows(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  from_port INTEGER NOT NULL,
  to_port   INTEGER NOT NULL,
  uncertain INTEGER NOT NULL CHECK(uncertain IN (0, 1)), crossed BLOB NOT NULL DEFAULT X'1B0B' CHECK(json_valid(crossed, 8)),
  PRIMARY KEY(blob_id, procedure, from_port, to_port),
  FOREIGN KEY(blob_id, procedure, from_port) REFERENCES candidate_macro_semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id, procedure, to_port) REFERENCES candidate_macro_semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_pointer_accesses(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  ordinal          INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  pointer          INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  width_kind       INTEGER NOT NULL CHECK(width_kind BETWEEN 0 AND 2),
  width_exact      TEXT,
  width_value      INTEGER,
  width_multiplier TEXT,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_pointer_aliases(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  pointer      INTEGER NOT NULL,
  origin       INTEGER NOT NULL,
  offset_kind  INTEGER NOT NULL CHECK(offset_kind BETWEEN 0 AND 3),
  offset_exact TEXT,
  offset_value INTEGER,
  offset_min   TEXT,
  offset_max   TEXT,
  strength     INTEGER NOT NULL CHECK(strength BETWEEN 0 AND 1),
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_pointer_invalidations(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  target_kind   INTEGER NOT NULL CHECK(target_kind BETWEEN 0 AND 1),
  target_value  INTEGER,
  target_origin INTEGER,
  cause         INTEGER NOT NULL CHECK(cause BETWEEN 0 AND 3),
  strength      INTEGER NOT NULL CHECK(strength BETWEEN 0 AND 1),
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_pointer_origins(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  origin         INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  kind           INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  place_kind     INTEGER,
  place_locator  INTEGER,
  place_location INTEGER,
  allocation     INTEGER,
  byte_extent    TEXT,
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, origin),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_points(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  point     INTEGER NOT NULL,
  block     INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_ports(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  port      INTEGER NOT NULL,
  kind      INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 11),
  a         INTEGER,
  b         INTEGER,
  root      INTEGER,
  selectors BLOB CHECK(selectors IS NULL OR json_valid(selectors, 8)),
  tail      INTEGER CHECK(tail IS NULL OR tail BETWEEN 0 AND 1),
  PRIMARY KEY(blob_id, procedure, port),
  CHECK((kind = 10) = (root IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure, root) REFERENCES candidate_macro_semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

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
  invocation             INTEGER NOT NULL CHECK(invocation BETWEEN 0 AND 1),
  dispatch_extensibility INTEGER NOT NULL CHECK(dispatch_extensibility BETWEEN 0 AND 1),
  call_boundary          INTEGER NOT NULL CHECK(call_boundary BETWEEN 0 AND 1),
  receiver_binding       INTEGER NOT NULL CHECK(receiver_binding BETWEEN 0 AND 1),
  construction_return    INTEGER NOT NULL CHECK(construction_return BETWEEN 0 AND 1),
  source                 INTEGER NOT NULL,
  evidence               INTEGER NOT NULL, has_declared_results INTEGER NOT NULL DEFAULT 0 CHECK(has_declared_results IN (0, 1)),
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_receiver_type_facts(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  call_site     INTEGER NOT NULL,
  member        INTEGER NOT NULL,
  receiver_type BLOB NOT NULL CHECK(json_valid(receiver_type, 8)),
  PRIMARY KEY(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_result_type_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 4),
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_scope_ends(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  place_kind     INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator  INTEGER,
  place_location INTEGER,
  at_kind        INTEGER NOT NULL CHECK(at_kind BETWEEN 0 AND 1),
  at_point       INTEGER,
  edge_source    INTEGER,
  edge_target    INTEGER,
  edge_kind      INTEGER,
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_source_mappings(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  mapping   INTEGER NOT NULL,
  locator   INTEGER NOT NULL,
  kind      INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  ast_node  INTEGER,
  PRIMARY KEY(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_statement_entries(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal   INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  point     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_switch_cases(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  switch       INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  value        INTEGER NOT NULL,
  source_point INTEGER NOT NULL,
  target_point INTEGER NOT NULL,
  edge_kind    INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, switch, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_switch_facts(
  blob_id              INTEGER NOT NULL,
  procedure            INTEGER NOT NULL,
  switch               INTEGER NOT NULL,
  kind                 INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  point                INTEGER NOT NULL,
  selector             INTEGER,
  selector_domain      INTEGER NOT NULL CHECK(selector_domain BETWEEN 0 AND 1),
  default_present      INTEGER NOT NULL CHECK(default_present IN (0, 1)),
  default_source_point INTEGER,
  default_target       INTEGER,
  default_kind         INTEGER,
  source               INTEGER NOT NULL,
  evidence             INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, switch),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_texts(
  blob_id INTEGER NOT NULL,
  text_id INTEGER NOT NULL,
  text    TEXT NOT NULL,
  PRIMARY KEY(blob_id, text_id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE candidate_macro_semantic_ir_values(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  value            INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 17),
  ordinal          INTEGER,
  multiplicity     INTEGER CHECK(multiplicity BETWEEN 0 AND 1),
  rest_domain      INTEGER CHECK(rest_domain BETWEEN 0 AND 3),
  rest_domain_text INTEGER,
  name             INTEGER,
  passing_mode     INTEGER CHECK(passing_mode BETWEEN 0 AND 2),
  flag             INTEGER CHECK(flag IN (0, 1)),
  magnitude        TEXT,
  float_bits       INTEGER,
  text             INTEGER,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL, static_type_class INTEGER NOT NULL DEFAULT 0 CHECK(static_type_class BETWEEN 0 AND 4), static_origin_call INTEGER, static_origin_ordinal INTEGER CHECK(
  (static_origin_call IS NULL AND static_origin_ordinal IS NULL) OR
  (static_origin_call IS NOT NULL AND static_origin_ordinal IS NOT NULL AND static_origin_ordinal >= 0)),
  PRIMARY KEY(blob_id, procedure, value),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX candidate_macro_semantic_ir_call_sites_receiver_location
  ON candidate_macro_semantic_ir_call_sites(blob_id, procedure, receiver_place_location)
  WHERE receiver_place_location IS NOT NULL;

CREATE INDEX candidate_macro_semantic_ir_call_sites_receiver_locator
  ON candidate_macro_semantic_ir_call_sites(blob_id, receiver_place_locator)
  WHERE receiver_place_locator IS NOT NULL;

CREATE INDEX candidate_macro_semantic_ir_partial_flows_to_port
  ON candidate_macro_semantic_ir_partial_flows(blob_id, procedure, to_port);

CREATE TABLE candidate_macro_semantic_ir_candidates(
  blob_id INTEGER NOT NULL REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  procedure INTEGER NOT NULL,
  call INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, call),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
