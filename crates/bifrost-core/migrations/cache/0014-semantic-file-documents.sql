-- The embedding document now includes the workspace-relative path. A blob OID
-- alone therefore no longer determines its vector, and the former summary and
-- component vectors are incompatible. Semantic data is rebuildable; discard it
-- while preserving every analyzer and semantic-pack table in this unified DB.
DELETE FROM semantic_blobs;
DELETE FROM semantic_vectors;
DELETE FROM semantic_component_vectors;
DELETE FROM semantic_blob_summaries;

DROP TABLE semantic_blob_chunks;
DROP TABLE semantic_blob_summaries;
DROP TABLE semantic_component_vectors;
DROP TABLE semantic_vectors;
DROP TABLE semantic_blobs;

CREATE TABLE semantic_files(
  blob_oid        TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
  rel_path        TEXT NOT NULL CHECK(length(rel_path) > 0),
  language        TEXT,
  materialized_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(blob_oid, rel_path)
) WITHOUT ROWID, STRICT;

CREATE TABLE semantic_file_chunks(
  blob_oid    TEXT NOT NULL,
  rel_path    TEXT NOT NULL,
  chunk_ord   INTEGER NOT NULL,
  symbol      TEXT NOT NULL,
  start_line  INTEGER,
  end_line    INTEGER,
  fts_tokens  TEXT NOT NULL,
  vector_hash BLOB NOT NULL CHECK(length(vector_hash) = 32),
  PRIMARY KEY(blob_oid, rel_path, chunk_ord),
  FOREIGN KEY(blob_oid, rel_path)
    REFERENCES semantic_files(blob_oid, rel_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX semantic_file_chunks_by_vector
  ON semantic_file_chunks(vector_hash);

CREATE TABLE semantic_vectors(
  vector_hash BLOB PRIMARY KEY CHECK(length(vector_hash) = 32),
  dim         INTEGER NOT NULL,
  vector      BLOB NOT NULL
) WITHOUT ROWID, STRICT;

UPDATE cache_state
SET embed_fingerprint = NULL,
    chunker_version = NULL,
    bm25_tokenizer_version = NULL;
