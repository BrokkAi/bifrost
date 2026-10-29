-- Preserve receiver storage until query-time method/field selection (#7150).
-- Rebuild to add the composite, blob/procedure-scoped place foreign keys.
-- Existing rows keep an absent selection; the new producer epoch invalidates
-- their cached semantics independently of this compatible store migration.
CREATE TABLE semantic_ir_call_sites_v214(
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
    REFERENCES semantic_ir_locators(blob_id, locator) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, receiver_place_location)
    REFERENCES semantic_ir_memory_locations(blob_id, procedure, location) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO semantic_ir_call_sites_v214(
  blob_id, procedure, call_site, point, invocation_mode, execution_timing,
  callee, receiver, result, thrown, normal_results, target_resolution, targets,
  target_evidence, normal_continuation, normal_target, exceptional_continuation,
  exceptional_target, source, evidence
)
SELECT blob_id, procedure, call_site, point, invocation_mode, execution_timing,
  callee, receiver, result, thrown, normal_results, target_resolution, targets,
  target_evidence, normal_continuation, normal_target, exceptional_continuation,
  exceptional_target, source, evidence
FROM semantic_ir_call_sites;

DROP TABLE semantic_ir_call_sites;
ALTER TABLE semantic_ir_call_sites_v214 RENAME TO semantic_ir_call_sites;

-- Parent-place deletion must seek the exact receiver place, not scan the
-- containing blob once per parent row.
CREATE INDEX semantic_ir_call_sites_receiver_locator
  ON semantic_ir_call_sites(blob_id, receiver_place_locator)
  WHERE receiver_place_locator IS NOT NULL;
CREATE INDEX semantic_ir_call_sites_receiver_location
  ON semantic_ir_call_sites(blob_id, procedure, receiver_place_location)
  WHERE receiver_place_location IS NOT NULL;
