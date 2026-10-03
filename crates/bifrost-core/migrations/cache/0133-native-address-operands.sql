-- Add runtime/addressable operand filters for address-of expressions.
-- Preserve existing transfers while adding codes 6 (addressable runtime input)
-- and 7 (any runtime input), both producing non-addressable runtime values.
-- No table references transfers; their only foreign key points to the interior.
CREATE TABLE resolution_type_transfers_next(
  blob_id                     INTEGER NOT NULL,
  source_slot                 INTEGER NOT NULL CHECK(source_slot >= 0),
  rule                        INTEGER NOT NULL CHECK(rule >= 0),
  target_slot                 INTEGER NOT NULL CHECK(target_slot >= 0),
  kind                        INTEGER NOT NULL CHECK(kind >= 0),
  indirection_delta           INTEGER NOT NULL,
  reference_indirection_delta INTEGER NOT NULL,
  value_transform             INTEGER NOT NULL CHECK(value_transform BETWEEN 0 AND 7),
  completion                  BLOB CHECK(completion IS NULL OR json_valid(completion, 8)),
  PRIMARY KEY(blob_id, source_slot, rule),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO resolution_type_transfers_next
SELECT * FROM resolution_type_transfers;
DROP TABLE resolution_type_transfers;
ALTER TABLE resolution_type_transfers_next RENAME TO resolution_type_transfers;
CREATE UNIQUE INDEX resolution_type_transfers_rule
  ON resolution_type_transfers(blob_id, rule);
CREATE INDEX resolution_type_transfers_target
  ON resolution_type_transfers(blob_id, target_slot);
