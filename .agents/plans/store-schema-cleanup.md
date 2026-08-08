# Replace the analyzer store's opaque blobs with relational rows

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

The canonical rules for ExecPlans in this repository are in `.agents/PLANS.md`, from the
repository root. This document must be maintained in accordance with that file.

## Purpose / Big Picture

Bifrost keeps its analyzer results in a rebuildable SQLite cache at
`.bifrost/cache/bifrost_cache.v<N>.db`. Ten of that database's columns do not hold a value; they
hold a serialized Rust structure. A serialized structure is a byte string produced by the
`bincode` library (or, in one case, by `serde_json`) that only Rust code can interpret. SQL
cannot filter on it, cannot index it, cannot constrain it, and cannot report it. Every read of
such a column therefore decodes the entire structure even when the caller wanted one field, and
every invariant inside the structure lives in a Rust method body instead of in the schema.

After this plan, those columns are ordinary rows and ordinary columns. Concretely, someone can
open the cache with the `sqlite3` command line and ask questions that are impossible today, for
example "which files import `serde` under a wildcard" or "which C++ template alias points at
`absl::Span`", and get an answer from SQL. Inside Bifrost the same change removes decode work
from measured hot paths and moves invariants such as "this record must name a code unit" from a
Rust `if` into a schema `CHECK` and a foreign key.

The design of record is `.agents/docs/store-relational-schema-design-2026-08.md`. The measured
substrate under that design is `.agents/docs/opaque-blob-inventory-2026-08.md`. Both are checked
in. This plan does not restate their measurements; it states the work, its order, and its state.

The whole plan is cheap for one structural reason, and every step depends on it: the cache is a
rebuildable artifact. The database file is named for its schema version, and the schema version
is the number of migrations, so a new migration means a new, empty file and a full re-analysis.
There is no dual-write period and no data migration. Each step is new DDL plus a new writer plus
a new reader, in one commit, with the old column gone in that same commit. Backward
compatibility is explicitly not a requirement here (AGENTS.md).

## Progress

- [x] (2026-08-08) Check in the measured inventory as `.agents/docs/opaque-blob-inventory-2026-08.md`;
      flip the design document's status to APPROVED, IMPLEMENTING; seed this ExecPlan.
- [x] (2026-08-08) Step 1, imports merge. Migration 0018 drops `import_details` and gives
      `import_statements` the `ImportInfo` scalars plus `import_path_segments`,
      `import_lexical_scopes`, and `import_lexical_prefixes`. Schema version 18, epoch salt v8.
      Landed as 7737ec9f (schema, writers, readers, Go and C# write-side cleanups) and 8f9cc55b
      (frozen-equivalence, schema, cascade, content-stability, cost, and EQP tests plus the
      Scala and TypeScript reconciliation pins).
- [ ] Step 2, signature split: `SignatureMetadata`'s fourteen scalars move onto `unit_signatures`;
      its parameter list and its two type arenas become child tables.
- [ ] Step 3, supertype lookup paths: replace the dual-shape JSON `unit_supertypes.lookup_path`
      with a `relation_kind` column and three child tables.
- [ ] Step 4, materialization records: replace the bincode union payload with columns plus
      variant CHECKs plus the missing foreign key to `code_units`.
- [ ] Step 5, `code_units.fq_segments`: replace the hand-rolled `FQ2` framing with
      `code_unit_fq_segments` rows and invert the authority between blob and columns.
- [ ] Step 6, C++ template metadata: flatten the recursive `CppTemplateTerm` into an arena table.
- [ ] Step 7, `scala_exports`: per-export rows, shaped like `rust_exports` from migration 0016.

Steps are independent. Any one of them can ship alone, and the order above is the design's
order by measured value.

## Surprises & Discoveries

- Observation: SQLite's `ALTER TABLE ... DROP COLUMN` accepts a column carrying its own
  single-column `CHECK`; the documented restriction is about a column named in a *table*
  CHECK. That turned the `blob_meta.import_count` removal from a table rebuild into one
  statement, which matters because two `cache_db` tests pin that later migrations stay additive
  for an already-populated cache and a rebuild would have dropped `blob_meta` rows and orphaned
  the two tables whose foreign keys point at it.
  Evidence: `ALTER TABLE blob_meta DROP COLUMN import_count` against a database built from
  migrations 0001 to 0017 succeeded and left every other CHECK in place;
  `populated_v5_cache_migrates_additively_to_v7` and
  `analyzer_migrations_preserve_populated_v3_rows_with_lazy_payload_costs` both fail against
  the rebuild version and pass against this one.

- Observation: `FileState::import_statements` and `FileState::imports` are two independently
  produced lists, not two views of one list, and for Scala and TypeScript they have different
  lengths. Merging the two tables therefore cannot preserve both; it necessarily makes the
  statement list a projection of the binding list.
  Evidence: the inventory's section 1.6 measured scala 2 statements against 3 details and
  typescript 3 against 4 in the polyglot fixture. In the source, Scala pushes one raw
  declaration string in `crates/bifrost-analysis/src/analyzer/scala/declarations.rs`
  (`collect_scala_imports`) while `scala_import_infos_from_node_with_prefixes` emits one
  `ImportInfo` per selector with a re-rendered `raw_snippet`.

## Decision Log

- Decision: `ImportInfo` survives as the hydrated shape rather than dissolving into per-call-site
  column reads.
  Rationale: about forty consumers across ten language modules take it by value, and several take
  it as a slice from a bulk read. Dissolving it is a consumer-retirement decision with its own
  measurements, not a consequence of where the bytes live. The storage change stands alone.
  Date/Author: 2026-08-08, Fable/Opus.

- Decision: `declaration_start_byte` doubles as the structured path's presence marker instead of
  a separate `has_path` flag.
  Rationale: `StructuredImportPath` always carries a declaration start byte, so the two columns
  would always agree, and two columns that must agree eventually disagree. A NULL here means the
  three child tables hold nothing for the row, which the DDL states.
  Date/Author: 2026-08-08, Fable/Opus.

- Decision: `ImportInfo` gains `is_global` and the table an `is_global` column, which the approved
  design's column list did not name.
  Rationale: the design says C#'s twelve snippet-parsing sites should read `path_kind` and
  segments instead. Five of them do. The other seven detect `global using` by matching the prefix
  "global using " against the snippet, and globalness is orthogonal to the path kind -- `global
  using static X` is legal -- so no value of a three-valued path-kind enum can carry it. Leaving
  the text test alive next to a structured path is exactly the smell the merge exists to remove.
  Date/Author: 2026-08-08, Fable/Opus.

- Decision: `import_statements()` collapses runs of equal adjacent snippets rather than returning
  one entry per binding.
  Rationale: the accessor's callers treat an entry as a statement. `module_import_skeleton` joins
  them into a summary and the Java and C++ resolvers iterate them, so a TypeScript declaration
  binding three names would print three identical lines and do the same work three times.
  Bindings of one declaration are contiguous because every adapter emits them while walking that
  declaration, so adjacency is sufficient and no second stored list is needed.
  Date/Author: 2026-08-08, Fable/Opus.

- Decision: the bounded read's byte budget prices the parent row's own text and not the child
  rows.
  Rationale: `statement` is the only import column that can be arbitrarily large, and the child
  rows are pieces of the same declaration, so budgeting `statement` bounds them within a small
  constant factor. Correlated subqueries over three child tables inside the bounded query would
  buy exactness at the cost of the clean indexed plan the EQP pin asserts.
  Date/Author: 2026-08-08, Fable/Opus.

- Decision: track the seven steps in this one ExecPlan rather than one plan per step.
  Rationale: the steps share one substrate, one set of cross-cutting schema rules, and one
  migration corridor, so a single Decision Log keeps the reasoning for later steps next to the
  precedent set by earlier ones. Splitting would force each file to restate the same context.
  Date/Author: 2026-08-08, Fable/Opus.

## Outcomes & Retrospective

Step 1, 2026-08-08. An import is now one row per binding in one table, the duplicate snippet is
gone, and the two ordinal sequences that were never co-keyed are one sequence by construction.
Four things came out of it that were not in the design:

The design assumed `path_kind` and segments would retire all twelve of C#'s snippet-parsing
sites. They retire five. The other seven ask whether a `using` is `global`, which is orthogonal
to the path kind, so the merge had to add a column and an `ImportInfo` field for it. The general
lesson for the remaining steps: count the consumers a step claims to retire before promising the
retirement, because "read the structure instead of the text" only works if the structure has a
place for every fact the text carried.

`FileState::import_statements` could not survive as an independent list, which the design said in
one clause and which turned out to be the widest part of the change: fifteen adapters wrote to
it. Removing it is what forces the Scala and TypeScript reconciliation, and it is why this step
touched ten language modules rather than the store alone.

The migration corridor cares about populated caches even though the store file name embeds the
schema version. Two `cache_db` tests pin that later migrations stay additive, so a table rebuild
is not free even when the new binary would never open the old file. `DROP COLUMN` was available
and is the right tool here; a later step that genuinely needs a rebuild will have to argue with
those tests first.

What remains from this step: `rust_import_targets` (migration 0016) still overlaps the merged
table for Rust, which the design says to collapse only once the consumer retirement plan settles.
Nothing else is outstanding.

## Context and Orientation

Read this section as if you have never seen the repository.

The analyzer parses a source file into a `FileState` (defined in
`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs`). `FileState` is the parse
product: declarations, ranges, signatures, imports, and so on. The store persists a `FileState`
into the SQLite cache keyed by the file's content hash, called a *blob oid*, together with the
*language key*. Two byte-identical files share one blob row, so no persisted column may be
derived from a file path; anything path-derived is recomputed on read from the live file. That
rule is called *content stability* in this repository and it constrains every step here.

All store code is in `crates/bifrost-analysis/src/analyzer/store/mod.rs`. All schema is in
`crates/bifrost-core/migrations/cache/`, one numbered `.sql` file per migration, listed in
`CACHE_MIGRATION_SQL` in `crates/bifrost-core/src/cache_db.rs`. `CURRENT_MIGRATION_VERSION` in
that file must equal the number of entries; a compile-time assertion enforces it. The database
file name embeds that version, so bumping it starts a fresh, empty database and the new
migration always runs against a schema freshly built by all earlier migrations. That is why a
step may simply `DROP TABLE` and `CREATE TABLE` rather than `ALTER` its way forward.

Separately from the schema version there is an *epoch salt*: the constant `STORE_EPOCH_SALT` in
`crates/bifrost-analysis/src/analyzer/store/epoch.rs`. It is hashed into the analysis epoch, so
changing it invalidates persisted analyzer rows without changing the schema. A step that changes
what the writer records, even without changing the schema, must bump it. A step that changes the
schema bumps both, because the two answer different questions and a reader of the code should
not have to reason about which one was sufficient.

The cross-cutting schema rules, from the design document, apply to every table any step adds:
`STRICT`; `WITHOUT ROWID` with `(blob_oid, lang, ...)` leading, so per-blob reads and per-blob
deletes stay clustered range scans; `ON DELETE CASCADE` reaching every row from `blobs`; booleans
as `INTEGER CHECK(x IN (0, 1))`; `CHECK(ordinal >= 0)` on every ordinal; `CHECK(start <= end)` on
every span pair; closed vocabularies as `TEXT` with a `CHECK(x IN (...))` list. Nothing
path-derived. Every new table's rows counted by the batch cost model, which is the pair of
`logical_rows` and `payload_bytes` numbers the store keeps per blob so garbage collection can
price a blob; both the prepared write path and the direct write path must agree with the SQL
fallback in `persisted_blob_mutation_cost_fallback_sql`. Every new read query gets an
`EXPLAIN QUERY PLAN` assertion in a test that names the index it must use.

Two more repository terms used below. A *frozen-equivalence test* is a test that keeps the old
decoder alive under `#[cfg(test)]` only, and asserts that hydrating a value from the new rows
produces exactly the value the old decoder would have produced from the old bytes; it is how a
step proves that relational storage lost nothing. *Fail-before discipline* means running each new
test against the pre-change code and confirming it fails for the intended reason before claiming
that passing afterwards means anything.

## Plan of Work

### Step 1: imports merge

Today one import is stored twice. `import_statements(blob_oid, lang, ordinal, statement)` holds
the raw source text of an import declaration. `import_details(blob_oid, lang, ordinal, info)`
holds a bincode `ImportInfo`, whose first field `raw_snippet` is the same text. The inventory
measured that text as byte-identical at the same ordinal in eight of ten languages and as 15 to
53 percent of the blob's bytes. In the other two languages, Scala and TypeScript, the two tables
do not even have the same number of rows, so their ordinals are not co-keyed and no join between
them is sound.

The merge deletes `import_details` and gives `import_statements` the `ImportInfo` scalars, so
there is exactly one row per import binding and `statement` is that binding's snippet, stored
once. Three narrow child tables hold the three variable-length parts of the structured path.
`ImportInfo` survives in Rust as the hydrated shape, because roughly forty consumers across ten
language modules take it by value; dissolving it into per-call-site column reads is a separate,
later decision that belongs with the consumer retirement work, not with the storage change.

Because the merged table has one row per binding, `FileState::import_statements` stops being an
independently produced list and becomes the snippets of `FileState::imports`. For eight
languages nothing changes. For Scala the reported statements become the per-selector rendered
snippets (`import a.B`, `import a.C`) instead of the single source declaration
(`import a.{B, C}`). For TypeScript the bindings of one declaration share one snippet, so the
accessor collapses runs of equal adjacent snippets to keep "one entry per statement" true. Both
outcomes are pinned by a test per language so that the reconciliation is a stated contract
rather than an accident.

Two write-side cleanups ride along, both of them cases where a consumer re-parses text that the
parser already had in structured form, which the repository's design philosophy prohibits. Go
stores its whole import path as a single segment and then five call sites re-extract the path
from the raw snippet with whitespace splitting and quote trimming; Go now stores the path
properly segmented and those call sites read `render_segments("/")`. C# stores no structured
path at all and then twelve call sites re-parse the snippet with `strip_prefix`, `starts_with`,
and `contains('=')`; C# now stores segments, a path kind, and a `global using` flag, and those
call sites read them.

### Steps 2 to 7

Not yet started. The design document specifies each one; this plan will gain a subsection per
step, in the shape of the Step 1 subsection above, when that step begins.

## Concrete Steps

Work from the repository root, `/mnt/optane/bifrost-nlp`.

For Step 1 the schema change is `crates/bifrost-core/migrations/cache/0018-import-bindings.sql`,
registered in `crates/bifrost-core/src/cache_db.rs` by adding an `include_str!` constant, adding
it to `CACHE_MIGRATION_SQL`, raising `CURRENT_MIGRATION_VERSION` to 18, and adding the matching
`execute_batch` line to the `CURRENT_SCHEMA_OBJECTS` test fixture in the same file. The epoch
salt in `crates/bifrost-analysis/src/analyzer/store/epoch.rs` is bumped in the same commit.

Focused validation while iterating, with a per-crate test run:

    cargo nextest run -p brokk-bifrost-analysis -p brokk-bifrost-core

Whole-suite validation for the import surface:

    cargo nextest run --workspace -E 'test(/import|suite_analyzers|suite_usages/)'

The featureless clippy gate that must be clean before any commit:

    cargo clippy --workspace --all-targets -- -D warnings

The `--workspace` flag is required: the root manifest sets `default-members = ["."]`, so without
it clippy lints only the facade package and a broken `#[cfg(test)]` module in a member crate
passes unnoticed.

## Validation and Acceptance

Acceptance for Step 1 is behavioral, and each item below is a test that fails before the change
and passes after.

Round-trip equivalence: for a fixture covering every language's import shape, an `ImportInfo`
written to rows and read back equals the same `ImportInfo` written to a bincode blob and read
back by the frozen decoder. The fixture must cover the pathless languages (C++, Ruby, C#), the
Scala shape that is the only user of lexical prefixes, the Rust shape that uses lexical scopes,
Go's segmented path, Java's and Python's path kinds, and the wildcard and alias forms.

Schema behavior: inserting a row with an out-of-range ordinal, a non-boolean flag, an unknown
path kind, or an inverted binder span is rejected by SQLite, not by Rust. Deleting a blob removes
its import rows and all three child tables' rows. Writing the same content through the prepared
path and through the direct path produces byte-identical rows. The cost model's logical row count
rises by exactly the number of child rows written.

Query cost: `EXPLAIN QUERY PLAN` for each new read shows a search using the primary key, never a
table scan.

Cross-language reconciliation: a Scala test and a TypeScript test each pin the exact statement
list the analyzer now reports for a declaration that binds several names.

## Idempotence and Recovery

Every step is safe to re-run because the cache is derived data. If a migration is edited after
being run locally, delete the `.bifrost/cache/bifrost_cache.v<N>.db` file for the affected
version and let the next run rebuild it. Never edit a migration file that has shipped in a
release; append a new one instead, which is the rule in
`crates/bifrost-core/migrations/cache/README.md`.

Nothing in this plan authorizes a version change, a tag, a publication, or a deployment.

## Artifacts and Notes

Step 1's landed DDL is `crates/bifrost-core/migrations/cache/0018-import-bindings.sql`. Its
shape, with the comments stripped:

    CREATE TABLE import_statements(
      blob_oid TEXT NOT NULL, lang TEXT NOT NULL,
      ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
      statement TEXT NOT NULL,
      is_wildcard INTEGER NOT NULL CHECK(is_wildcard IN (0, 1)),
      is_global INTEGER NOT NULL CHECK(is_global IN (0, 1)),
      identifier TEXT, alias TEXT,
      path_kind TEXT CHECK(path_kind IN ('namespace','import_from','static_member')),
      declaration_start_byte INTEGER CHECK(declaration_start_byte >= 0),
      binder_start INTEGER CHECK(binder_start >= 0),
      binder_end INTEGER CHECK(binder_end >= 0),
      CHECK((binder_start IS NULL) = (binder_end IS NULL)),
      CHECK(binder_start IS NULL OR binder_start <= binder_end),
      CHECK(path_kind IS NULL OR declaration_start_byte IS NOT NULL),
      PRIMARY KEY(blob_oid, lang, ordinal),
      FOREIGN KEY(blob_oid, lang) REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
    ) WITHOUT ROWID, STRICT;

    import_path_segments(blob_oid, lang, ordinal, seg_ordinal, segment TEXT NOT NULL)
    import_lexical_scopes(blob_oid, lang, ordinal, scope_ordinal, start_byte, end_byte)
    import_lexical_prefixes(blob_oid, lang, ordinal, prefix_ordinal, prefix TEXT NOT NULL)

Each child table has `PRIMARY KEY(blob_oid, lang, ordinal, <its ordinal>)`, `CHECK(... >= 0)` on
both ordinals, and `FOREIGN KEY(blob_oid, lang, ordinal) REFERENCES import_statements(...) ON
DELETE CASCADE`; `import_lexical_scopes` also carries `CHECK(start_byte <= end_byte)`. The
migration ends with `ALTER TABLE blob_meta DROP COLUMN import_count`.

The fail-before evidence, one mutation at a time with the file restored after each:

    mutation 1: writer stops persisting lexical prefixes
      FAIL import_child_rows_follow_the_structured_path
      FAIL import_rows_hydrate_what_the_frozen_blob_decoder_produced
    mutation 2: writer forgets is_global
      FAIL import_rows_hydrate_what_the_frozen_blob_decoder_produced
    mutation 3: reader drops the binder span
      FAIL import_rows_hydrate_what_the_frozen_blob_decoder_produced
    mutation 4: cost model counts only the parent rows
      FAIL import_child_rows_are_counted_by_the_cost_model
    mutation 5: segments child table stops cascading
      FAIL deleting_a_blob_cascades_every_import_table
    mutation 6: path_kind no longer implies a structured path
      FAIL import_row_constraints_are_enforced_by_the_schema
    mutation 7: import_statements() stops collapsing adjacent equal snippets
      FAIL typescript_multi_binding_import_reports_one_statement_per_declaration

`scala_import_test::test_static_import` is its own fail-before: against the pre-merge code it
expected `import foo.bar.{Baz as Bar}` and the merge makes it `import foo.bar.Baz as Bar`.

The EQP plans `import_reads_use_the_import_primary_keys` asserts, all of them a bare
`SEARCH ... USING PRIMARY KEY` with no `SCAN` and no `USE TEMP B-TREE`:

    SELECT <scalars> FROM import_statements WHERE blob_oid = ? AND lang = ? ORDER BY ordinal
    SELECT blob_oid, ordinal, segment FROM import_path_segments
      WHERE lang = ? AND blob_oid IN (?, ?) ORDER BY blob_oid, ordinal
    ... the same for import_lexical_prefixes and import_lexical_scopes

The bulk parent read keeps the `blob_meta` join and therefore the ordering b-tree it already had
before this change; `replacement_cost_set_uses_only_bounded_primary_key_probes` covers the cost
SQL's new `import_path_segments` and `import_lexical_prefixes` branches.

Validation for step 1: `cargo nextest run -p brokk-bifrost-analysis -p brokk-bifrost-core` ran
2040 tests with three failures, all on the pre-existing tolerated list for this revision (the JVM
source-and-class-jar artifact test and the two `live_oid_resolution` concurrency tests).
`cargo nextest run --workspace -E 'test(/import|suite_analyzers|suite_usages/)'` ran 669 tests
with none failing. `cargo clippy --workspace --all-targets -- -D warnings` is clean.

## Interfaces and Dependencies

Step 1 keeps `brokk_bifrost_core::analyzer::model::ImportInfo` as the hydrated shape and adds one
field to it:

    pub struct ImportInfo {
        pub raw_snippet: String,
        pub is_wildcard: bool,
        pub is_global: bool,
        pub identifier: Option<String>,
        pub alias: Option<String>,
        pub path: Option<StructuredImportPath>,
        pub binder_span: Option<Span>,
    }

`is_global` records an import that binds beyond its own file. C#'s `global using` is the only
language form that sets it today; every other adapter sets `false`. It exists because seven call
sites detected that form by testing `raw_snippet.trim_start().starts_with("global using ")`, and
the merge's whole purpose is to stop consumers from re-reading structure out of text.
