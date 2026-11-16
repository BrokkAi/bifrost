-- #11251: candidate records replace the bare alternate call list. Each row names the
-- invocation by its source anchor (a lookup index inside one blob's artifact only),
-- the base call it replaces and how the alternate realizes it:
--   'call'                        the alternate lowers the invocation to the call in alternate_call;
--   'intrinsic'                   the alternate lowers it to control flow and values (no call);
--   'lexical_no_items_introduced' the alternate keeps the same logical call and proves the
--                                 invocation introduces no items into the lexical scope.
-- alternate_call is set exactly for 'call'. An invocation nested in the operands of an
-- opaque candidate names the nearest enclosing base candidate call in base_call, so several
-- rows of one procedure may share a base_call; the anchor is the row's identity.
-- Old rows hold only an alternate call and cannot supply an anchor or a base call. Their
-- publications are rejected by the IR schema and rows versions that move with this
-- migration, so the table is rebuilt empty and those blobs are republished.
DROP TABLE candidate_macro_semantic_ir_candidates;

CREATE TABLE candidate_macro_semantic_ir_candidates(
  blob_id INTEGER NOT NULL REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE,
  procedure INTEGER NOT NULL,
  anchor_start INTEGER NOT NULL CHECK(anchor_start >= 0),
  anchor_end INTEGER NOT NULL CHECK(anchor_end > anchor_start),
  base_call INTEGER NOT NULL CHECK(base_call >= 0),
  realization TEXT NOT NULL CHECK(realization IN ('call', 'intrinsic', 'lexical_no_items_introduced')),
  alternate_call INTEGER CHECK(alternate_call IS NULL OR alternate_call >= 0),
  CHECK((realization = 'call') = (alternate_call IS NOT NULL)),
  PRIMARY KEY(blob_id, procedure, anchor_start, anchor_end),
  FOREIGN KEY(blob_id, procedure) REFERENCES candidate_macro_semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
