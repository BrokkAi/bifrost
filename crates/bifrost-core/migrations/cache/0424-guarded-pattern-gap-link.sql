-- Compatible: additive nullable links preserve old candidates as unlinked;
-- NULL grants no discharge. Producer identities rebuild newly linked rows.
-- #9925: procedure-local gap ordinal, never a SQLite row identity.
-- NULL on legacy or unlinked candidates authorizes no discharge.
ALTER TABLE semantic_ir_guarded_pattern_projections
  ADD COLUMN gap INTEGER CHECK(gap IS NULL OR gap >= 0);
CREATE UNIQUE INDEX semantic_ir_guarded_pattern_gap
  ON semantic_ir_guarded_pattern_projections(blob_id, procedure, gap)
  WHERE gap IS NOT NULL;
-- Candidate-macro rows use the same typed projection columns and link contract.
ALTER TABLE candidate_macro_semantic_ir_guarded_pattern_projections
  ADD COLUMN gap INTEGER CHECK(gap IS NULL OR gap >= 0);
CREATE UNIQUE INDEX candidate_macro_semantic_ir_guarded_pattern_gap
  ON candidate_macro_semantic_ir_guarded_pattern_projections(blob_id, procedure, gap)
  WHERE gap IS NOT NULL;
