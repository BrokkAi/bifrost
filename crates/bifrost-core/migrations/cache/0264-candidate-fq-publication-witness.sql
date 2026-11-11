-- A witness identifies one complete publication within this database lineage.
-- Future blob_meta rebuilds must preserve both the witness and this sequence.
CREATE TABLE blob_publication_witness_sequence(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  store_nonce BLOB NOT NULL CHECK(length(store_nonce) = 16),
  next_witness INTEGER NOT NULL CHECK(next_witness > 0)
) STRICT;
INSERT INTO blob_publication_witness_sequence VALUES (1, randomblob(16), 1);

ALTER TABLE blob_meta ADD COLUMN publication_witness INTEGER
  CHECK(publication_witness IS NULL OR publication_witness > 0);
UPDATE blob_meta SET publication_witness = blob_id WHERE is_complete = 1;
UPDATE blob_publication_witness_sequence
SET next_witness = (SELECT COALESCE(MAX(publication_witness), 0) + 1 FROM blob_meta);

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

CREATE TRIGGER code_unit_fq_segments_no_insert_after_completion
BEFORE INSERT ON code_unit_fq_segments
WHEN EXISTS (SELECT 1 FROM blob_meta WHERE blob_id = NEW.blob_id AND is_complete = 1)
BEGIN SELECT RAISE(ABORT, 'sealed FQ segments are immutable'); END;
CREATE TRIGGER code_unit_fq_segments_no_update_after_completion
BEFORE UPDATE ON code_unit_fq_segments
WHEN EXISTS (SELECT 1 FROM blob_meta
             WHERE blob_id IN (OLD.blob_id, NEW.blob_id) AND is_complete = 1)
BEGIN SELECT RAISE(ABORT, 'sealed FQ segments are immutable'); END;
CREATE TRIGGER code_unit_fq_segments_no_delete_after_completion
BEFORE DELETE ON code_unit_fq_segments
WHEN EXISTS (SELECT 1 FROM blob_meta WHERE blob_id = OLD.blob_id AND is_complete = 1)
 AND EXISTS (SELECT 1 FROM blobs WHERE id = OLD.blob_id)
BEGIN SELECT RAISE(ABORT, 'sealed FQ segments are immutable'); END;
