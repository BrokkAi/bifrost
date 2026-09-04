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

Migration `0035-signature-type-parameters-recorded.sql` adds one column that
says whether a signature row's `type_parameters` list was read or defaulted.
It invalidates nothing on its own: existing rows read back as unrecorded,
which is what their producers actually knew. The languages whose type
declarations now record the list bump their own per-language epoch salt.

Migration `0036-policy-evaluation-units.sql` persists policy evaluation units
and the base evaluations that published them. A unit row carries its key, the
rendered rows it produced as one JSON product column, and the digest of the
read set that licenses reusing it; `policy_read_keys` interns those reads as
ordinary columns and `policy_unit_reads` records the membership. A
`policy_evaluations` row records that one policy set evaluated completely over
one committed subtree, so a later `--diff-base` run reuses that work instead of
exporting and evaluating the base again. Unit rows follow their seed blob out
of the cache through `ON DELETE CASCADE`, which is exactly when the recorded
content is gone; evaluations are retired by an age and count sweep, because a
tree id has no blob to hang from.

Migration `0037-policy-evaluation-identities.sql` records what a base
evaluation concluded, not only what it computed. `policy_evaluation_identities`
holds the strong finding identities one policy set produced over one committed
subtree, per policy, which is exactly the set a `--diff-base` run joins its
head findings against. A warm base therefore serves every policy family,
including the taint and flow policies that publish no units at all, and no run
reconstructs base findings by merging units any more. The unit membership stays
as the age sweep's evidence that a unit belongs to a live evaluation, so
`policy_evaluations` and `policy_evaluation_units` are rebuilt without the
columns the replay was their only reader for (`unit_count`,
`analyzed_source_bytes`, `analyzed_file_count`, and the membership `ordinal`).
Neither table carries its rows across: an evaluation recorded before this
migration has no identities, and an absent identity set is indistinguishable
from an empty one, so the rebuild is what makes every surviving row
authoritative about its own identities. The units themselves are content-keyed
and survive.

Migration `0038-policy-assert-file-units.sql` widens `policy_units` for the
assertion family. An assertion policy's work splits into one seed unit per file
for its subject query and one assert unit per subject file, whose product is the
findings that file's asserts produced rather than a query's rendered rows, so
`partition_kind` gains `assert_file`, `product_kind` gains `assert_file`, and
the two are required to agree. An assert unit is keyed by its file, that path's
blob, and the digest of the file's subject rows: two runs whose subject selector
bound different rows in the same bytes ask different questions of the same file,
and a key without that digest would answer the second with the first's findings.
`partition_digest` carries it and joins the unique index, which is why the table
is recreated rather than altered -- SQLite cannot add a column to an existing
index. `policy_unit_reads` and `policy_evaluation_units` are recreated with it
because each references `policy_units(unit_id)`. Nothing is carried across;
units are content-keyed, so the next run republishes what is still true.

Migration `0039-policy-binding-units.sql` widens `policy_units` once more, for
the relational half of the assertion family. A relational assertion policy runs
one query per declared row binding, and each of those queries is sliced by seed
file like any other, so `partition_kind` gains `binding`: a file, that path's
blob, and the digest of the binding's name, because two bindings of one policy
read the same seed files and a key without the binding would serve the second
binding's rows from the first binding's unit. A binding unit's product is
rendered rows, which is why `product_kind` stays tied to the assert partition
alone. Both changes are CHECK constraints -- the admitted partition kinds, and
which kinds carry a narrowing digest -- and SQLite cannot alter a CHECK in
place, so the table is recreated with `policy_unit_reads` and
`policy_evaluation_units`, which reference it. Nothing is carried across; units
are content-keyed, so the next run republishes what is still true.
Migration `0040-structural-fact-labels-from-registry.sql` stops enumerating
structural labels in the schema. Migration 0034 copied `NormalizedKind::LABELS`
and the `Role` labels into CHECK constraints on `structural_fact_nodes.kind` and
`structural_fact_roles.role`, and the copies lagged the registry: `module`,
`concurrent_spawn`, and `operator` were never added, so every file whose facts
carried one failed its insert and was re-extracted on every warm run (#2922).
Hydration already resolves each label through the registry's `from_label` and
rejects one it does not know, so the enumeration protected nothing. The two
columns keep `NOT NULL` and lose the list; every other CHECK is kept, and the
insert site asserts the registry round-trip in debug builds. The tables are
recreated with the `_new`-then-rename swap 0033 documents, children filled
before any parent is dropped so the cascades fire on empty old tables only, and
every existing row is carried across.


Migration `0041-policy-root-units.sql` admits the typestate family's fourth
partition. A typestate policy's work is one interprocedural solve per root
procedure, and one file declares many procedures, so `partition_kind` gains
`root`: a file, that path's blob, and the digest of the root's own mount-free
semantic locator, carried in `partition_digest` as the binding name is for a
binding unit. A root unit's product is what one iteration of the per-root loop
appended (that root's projected violations, the reasons its own analysis was
incomplete, and its counters), which is neither rendered rows nor a file's
findings, so `product_kind` admits `root` and is tied to the root partition as
`assert_file` is tied to the assert partition. Every change is a CHECK
constraint, so the table is recreated with `policy_unit_reads` and
`policy_evaluation_units`; nothing is carried across, because units are
content-keyed and the next run republishes what is still true.

Migration `0042-policy-selector-units.sql` admits the typestate family's other
half. A typestate policy's work is a compile and a solve; 0041 unitized the
solve, and this unitizes the compile, so `partition_kind` gains `selector`: one
seed file of one selector of the policy, with the digest of the selector's own
document path in `partition_digest`, because one policy compiles many selectors
over the same files and two of them keyed by the file alone would answer each
other's question. A selector unit's product carries the query's rows, so the
merge can check the cumulative caps a whole execution enforces, together with
the sites that seed file selected and what the execution took out of the
compile's shared semantic ledgers, so `product_kind` admits `selector` and is
tied to the selector partition as `root` is tied to the root partition. Every
change is a CHECK constraint, so the table is recreated with
`policy_unit_reads` and `policy_evaluation_units`; nothing is carried across,
because units are content-keyed and the next run republishes what is still
true.
