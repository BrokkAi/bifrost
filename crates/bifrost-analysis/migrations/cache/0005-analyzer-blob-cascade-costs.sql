-- Existing analyzer rows remain nullable and are costed through the legacy
-- indexed aggregate until they are naturally replaced. New writers persist
-- exact cascade costs transactionally with the blob root.
ALTER TABLE blobs
  ADD COLUMN cascade_logical_rows INTEGER
  CHECK(cascade_logical_rows IS NULL OR cascade_logical_rows >= 1);

ALTER TABLE blobs
  ADD COLUMN cascade_payload_bytes INTEGER
  CHECK(cascade_payload_bytes IS NULL OR cascade_payload_bytes >= 0);
