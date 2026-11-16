-- #11535/#10979: an unminted empty template is construction material only.
-- Preserve installed store identity and all consumed witness history.
DROP TRIGGER blob_meta_witness_after_insert;
DROP TRIGGER blob_meta_witness_after_completion;
ALTER TABLE blob_publication_witness_sequence RENAME TO publication_sequence_before_0420;
CREATE TABLE blob_publication_witness_sequence(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  store_nonce BLOB CHECK(store_nonce IS NULL OR length(store_nonce) = 16),
  next_witness INTEGER NOT NULL CHECK(next_witness > 0)
) STRICT;
INSERT INTO blob_publication_witness_sequence
  SELECT id, store_nonce, next_witness FROM publication_sequence_before_0420;
DROP TABLE publication_sequence_before_0420;

-- Keep this guard separate: only a private, unpublished StagedImport may
-- temporarily remove it in its single creation transaction.
CREATE TRIGGER blob_publication_sequence_nonce_immutable
BEFORE UPDATE ON blob_publication_witness_sequence
WHEN OLD.store_nonce IS NOT NULL AND NEW.store_nonce IS NOT OLD.store_nonce
BEGIN SELECT RAISE(ABORT, 'publication lineage nonce is immutable'); END;
CREATE TRIGGER blob_publication_sequence_monotonic
BEFORE UPDATE ON blob_publication_witness_sequence
WHEN NEW.id IS NOT OLD.id OR NEW.next_witness < OLD.next_witness
  OR (OLD.store_nonce IS NULL AND NEW.next_witness IS NOT OLD.next_witness)
BEGIN SELECT RAISE(ABORT, 'publication sequence cannot decrease, change key or advance unminted'); END;
CREATE TRIGGER blob_publication_sequence_no_delete
BEFORE DELETE ON blob_publication_witness_sequence
BEGIN SELECT RAISE(ABORT, 'publication sequence cannot be deleted'); END;
-- REPLACE's implicit DELETE does not fire delete triggers when recursive
-- triggers are OFF. BEFORE INSERT still sees the existing row and refuses.
CREATE TRIGGER blob_publication_sequence_no_replace
BEFORE INSERT ON blob_publication_witness_sequence
WHEN EXISTS(SELECT 1 FROM blob_publication_witness_sequence WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'publication sequence cannot be replaced'); END;

CREATE TRIGGER blob_meta_require_minted_insert
BEFORE INSERT ON blob_meta WHEN NEW.is_complete = 1
BEGIN
  SELECT RAISE(ABORT, 'publication lineage is not minted')
    WHERE NOT EXISTS(SELECT 1 FROM blob_publication_witness_sequence
                     WHERE id = 1 AND store_nonce IS NOT NULL);
  SELECT RAISE(ABORT, 'publication witness exhausted')
    WHERE COALESCE((SELECT next_witness FROM blob_publication_witness_sequence
                    WHERE id = 1), 9223372036854775807) >= 9223372036854775807;
END;
CREATE TRIGGER blob_meta_require_minted_completion
BEFORE UPDATE OF is_complete ON blob_meta
WHEN OLD.is_complete = 0 AND NEW.is_complete = 1
BEGIN
  SELECT RAISE(ABORT, 'publication lineage is not minted')
    WHERE NOT EXISTS(SELECT 1 FROM blob_publication_witness_sequence
                     WHERE id = 1 AND store_nonce IS NOT NULL);
  SELECT RAISE(ABORT, 'publication witness exhausted')
    WHERE COALESCE((SELECT next_witness FROM blob_publication_witness_sequence
                    WHERE id = 1), 9223372036854775807) >= 9223372036854775807;
END;
CREATE TRIGGER blob_meta_witness_after_insert
AFTER INSERT ON blob_meta WHEN NEW.is_complete = 1
BEGIN
  SELECT RAISE(ABORT, 'publication witness exhausted')
    WHERE COALESCE((SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1), 9223372036854775807) >= 9223372036854775807;
  UPDATE blob_meta SET publication_witness =
    (SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1)
    WHERE blob_id = NEW.blob_id;
  UPDATE blob_publication_witness_sequence SET next_witness = next_witness + 1 WHERE id = 1;
END;
CREATE TRIGGER blob_meta_witness_after_completion
AFTER UPDATE OF is_complete ON blob_meta
WHEN OLD.is_complete = 0 AND NEW.is_complete = 1
BEGIN
  SELECT RAISE(ABORT, 'publication witness exhausted')
    WHERE COALESCE((SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1), 9223372036854775807) >= 9223372036854775807;
  UPDATE blob_meta SET publication_witness =
    (SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1)
    WHERE blob_id = NEW.blob_id;
  UPDATE blob_publication_witness_sequence SET next_witness = next_witness + 1 WHERE id = 1;
END;
