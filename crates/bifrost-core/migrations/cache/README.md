# Unified cache migrations

`0018-current-baseline.sql` is the schema every store starts from. It is the
fold of the former migrations 0001..0018 and is named for the version it
produces, not for its position. The numbered files beside it carry a store
forward through the current version; version numbers remain explicit because
this chain can deliberately skip an unpublished number.

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

Migration `0024-live-definition-views.sql` makes completed-parse and
active-generation membership reusable schema interfaces for definition
queries. It adds views only: it does not persist a second path, package, or
declaration projection.

Migration `0027-relational-definition-set-views.sql` keeps stable and anchored
name access paths separate for set-oriented joins. It adds views only. The
split prevents SQLite from materializing the compound point-query views when a
bounded request relation drives a batch.

Migration `0028-retire-fq2.sql` removes the opaque `code_units.fq_segments`
identity envelope. Migration 0026 already populated the authoritative
`code_unit_fq_segments` relation; 0028 backfills parent-declared segment row and
byte counts for complete-read validation and bounded header admission, then
drops the redundant binary copy without invalidating analyzer rows.

Migration `0029-reverse-import-lookups.sql` adds reverse access paths for
structured import segments and type identifiers. Seed-directed relevance
queries intersect these indexes with their connection-local live blob set, so
they do not hydrate every file in a large workspace or admit historical blobs
from the shared content cache.

Migration `0030-reference-identifier-facts.sql` renames the cross-language
identifier relation to match its actual use in reference planning and adds an
independent epoch/count manifest. Epoch 1 has exactly the old row semantics,
so the migration carries every complete blob forward in SQL. A later extractor
epoch can selectively reconcile stale live blobs without invalidating stored
declarations, semantic chunks, or vectors.

Migration `0031-relational-definition-identifier-views.sql` gives identifier
definition lookups lean stable and anchored views without the unused path-name
arm of the wider exact-name projection.

Migration `0032-revisioned-workspace-projections.sql` replaces mutable
language-wide workspace rows with immutable, worktree-keyed revisions. Blob
facts remain shared while each analyzer pins path, package, anchor, and path
symbol queries to the revision it captured.

Migration `0033-intern-blob-ids.sql` interns each `(blob_oid, lang)` pair as an
integer `blobs.id` and rekeys content-addressed analyzer facts to that ID.

Migration `0034-relational-structural-facts.sql` replaces the opaque bincode
structural-facts snapshot with a manifest and normalized node, structural-role,
and occurrence-role rows. The relational schema retains the existing
whole-file hydration behavior while making the persisted facts queryable by
SQLite.
