# Unified cache migrations

`0018-current-baseline.sql` is the schema every store starts from. It is the
fold of the former migrations 0001..0018 and is named for the version it
produces, not for its position. The four files beside it carry a store from
version 18 to version 22, one version each.

`BASELINE_MIGRATION_VERSION` and `CURRENT_MIGRATION_VERSION` in
`src/cache_db.rs` name the two ends, and `CACHE_MIGRATIONS` writes the version
beside each file's SQL rather than inferring it from a position. Compile-time
assertions tie the list to both constants.

To change the cache schema, add one numbered file here and one entry to
`CACHE_MIGRATIONS`. Migration SQL must contain only schema/data changes, end
statements with semicolons, and omit transaction control and connection
PRAGMAs. All pending entries run in one transaction.

Never edit a released file, and never add a down migration. This cache is
derived data: a store from a newer schema is left alone, a store older than
the baseline is declined and rebuilt from scratch, and a damaged store under
this build's own name is rebuilt in place.

Do not prettify `0018-current-baseline.sql`. It is SQLite's own rendering of
the schema the folded migrations produced, down to the quoted table names and
the columns that sit after a table's closing parenthesis. SQLite stores a
table's defining text verbatim, so a store carried forward from an older
schema holds exactly this text, and `verify_upgraded_store` requires an
upgraded store and a fresh one to be indistinguishable.

`bridges/` holds SQL that is not a migration. A bridge repairs one recognized
foreign schema -- a store from a branch that numbered its migrations
differently -- onto a version of this chain. `RECOGNIZED_FOREIGN_STORES` in
`src/cache_db.rs` is the only caller and explains why such a store exists.

Migration `0022-drop-bm25-lexical-columns.sql` removes the two columns that
only served the deleted lexical (BM25) retrieval arm:
`semantic_file_chunks.fts_tokens` and `cache_state.bm25_tokenizer_version`.
Retrieval is dense only, so nothing reads them. Chunk and vector rows keep
their identities, so no cache is invalidated by this migration.
