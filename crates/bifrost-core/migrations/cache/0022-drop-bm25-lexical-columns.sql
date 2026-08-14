-- Semantic retrieval is dense only: the lexical (BM25) arm was measured to be a
-- net loss against a deeper dense arm and has been removed from the code. The
-- two columns that existed only to feed it go with it.
--
-- `fts_tokens` held the tokenized raw source of every function chunk, which was
-- read once per process to build a throwaway FTS5 index. It is the largest
-- text column in the chunk table. `bm25_tokenizer_version` recorded which
-- tokenizer produced those tokens.
--
-- Neither column participates in a primary key, index, CHECK, or foreign key,
-- so SQLite drops them in place. Chunk rows, vectors, and their identities are
-- untouched: no re-embedding and no re-materialization follow this migration.
ALTER TABLE semantic_file_chunks DROP COLUMN fts_tokens;
ALTER TABLE cache_state DROP COLUMN bm25_tokenizer_version;
