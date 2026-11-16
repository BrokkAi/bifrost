-- #12241: compatible additive migration: new runtime binary-operation table
-- and closed operator/RHS-reference CHECKs, plus its publication count column.
-- Operand indexes keep semantic-catalog foreign-key child probes bounded.
-- RHS reference evidence: 0 unknown, 1 shared, 2 mutable; derived from RHS AST.
-- user_version 424 fences older executables from reading this schema.
-- Source facts rederive via resolution-bundle-rust:12241-string-add-str-type;
-- an old blob must not be admitted as a complete empty operation inventory.
-- FQN-prefix downgrade inventory: none (no FQN columns or names change).
-- Undo: DROP TABLE resolution_binary_operations; ALTER TABLE
-- resolution_fragment_interiors DROP COLUMN expected_binary_operation_count;
-- then restore the previous user_version with the previous executable offline.
CREATE TABLE resolution_binary_operations (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  output_slot INTEGER NOT NULL CHECK(output_slot >= 0),
  left_slot INTEGER NOT NULL CHECK(left_slot >= 0),
  right_slot INTEGER NOT NULL CHECK(right_slot >= 0),
  operator INTEGER NOT NULL CHECK(operator IN (0,1,2,3,4,5,6,7,8,9)),
  right_reference INTEGER NOT NULL CHECK(right_reference IN (0,1,2)),
  PRIMARY KEY(blob_id, output_slot),
  FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, left_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, right_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_binary_operation_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_binary_operation_count >= 0);

CREATE INDEX resolution_binary_operations_left ON resolution_binary_operations(blob_id, left_slot);
CREATE INDEX resolution_binary_operations_right ON resolution_binary_operations(blob_id, right_slot);
