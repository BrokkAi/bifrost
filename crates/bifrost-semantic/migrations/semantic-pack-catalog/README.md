# Semantic-pack catalog migrations

The semantic-pack catalog is a rebuildable, cross-workspace database stored
beside immutable digest-addressed shard objects. It is independent from the
workspace-local unified cache migrations under `migrations/cache/`.

Append new forward-only migrations and increment the catalog version in
`analyzer/semantic_model/catalog/db.rs`. An older binary must reject a newer
`PRAGMA user_version` without modifying the database. Migration SQL contains
schema and data changes only, ends statements with semicolons, and contains no
transaction control or connection pragmas.

Current history:

- `0001-current-baseline.sql`: immutable pack, object, selector, source, and
  quarantine catalog.
- `0002-lifecycle.sql`: pins, workspace activations, reader leases, install
  reservations, and GC indexes.
- `0003-procedure-summaries.sql`: widens the generic shard payload-kind
  constraint while preserving shard, selector, and routing rows.
- `0004-generated-productions.sql`: records deterministic generated-pack
  production identities for reuse across workspaces.
- `0005-extraction-gaps.sql`: records release-bundle reject accounting and
  declaration-scoped extraction gaps without changing compiled manifests.
- `0006-extraction-source-entries.sql`: records typed artifact-relative source
  entries for file-level reject accounting without adding them to declaration
  gap lookup.
- `0007-acquisition-absence-receipts.sql`: records restart-safe verified
  acquisition absence and invalidates it through a trigger-maintained semantic
  catalog mutation epoch.
- `0008-generated-source-identities.sql`: records the read-free identity a
  generated production was learned under (a JDK's release digest and JMOD
  listing), so a later process can find the production without reading its
  artifacts. The row cascades with the production it names.
- `0009-generated-cache-epochs.sql`: removes the incomplete generated-production
  uniqueness index. The primary production digest includes the cache epoch,
  allowing revised producer output to coexist with earlier cached generations.
  Records the epoch for candidate selection. Historical rows remain stored;
  migration marks them current only if their canonical digest verifies against
  this binary's epoch. Unverified historical output is not activated.

- `0010-shard-validation.sql`: records bounded shard validation certificates and
  the verified generated-production view.
- `0011-native-compatibility.sql`: keeps legacy engine ranges while allowing
  schema-8 packs to store an absent range as NULL. The parent table and its
  dependent view are rebuilt transactionally, preserving existing bytes, child
  rows, indexes and mutation epochs. The caller disables foreign keys before
  opening this transaction, checks every foreign key before committing, and
  restores enforcement after success or rollback. Read-only older catalogs
  return `ReadOnlySchema` instead of migrating.
- `0012-unknown-types.sql`: widens the native, gate-free compatibility shape
  from schema 8 to schemas 8 and 9. It rebuilds the parent table and dependent
  view transactionally while preserving pack bytes, child rows, indexes,
  triggers, and mutation epochs. The caller disables foreign keys before the
  transaction, checks every foreign key before committing, and restores
  enforcement after success or rollback.
- `0013-callable-values.sql`: admits native schema-10 packs without a Bifrost
  compatibility gate.
- `0014-callable-value-rows.sql`: adds normalized rows and coverage for
  callable-value facts, leaving old shards unindexed until exact demand.
- `0015-structured-formals.sql`: admits native schema-11 packs with structured
  procedure formals. It rebuilds the parent table and generated-production
  view transactionally while preserving pack bytes, child rows, indexes,
  triggers, and mutation epochs; the caller validates foreign keys before
  publishing the new catalog version.
- `0016-semantic-model-schema.sql`: admits semantic-model schema 13, combining
  reviewed channel-close effects, returned-callable bindings, and structured
  procedure formals. It rebuilds the parent table and dependent view
  transactionally while preserving pack rows and catalog state.
- `0017-exact-go-source-rows.sql`: stores verified Go artifact source bytes and
  package membership as readable rows for exact native callable materialization.
  It preserves schema-13 compatibility and all existing catalog state.
- `0018-semantic-model-schema-v14.sql`: admits semantic-model schema 14 while
  preserving schema-8 through schema-13 pack rows and catalog state.
- `0019-semantic-model-schema-v15.sql`: admits semantic-model schema 15, whose
  parameter-role and module-value facts are structured; it preserves earlier
  pack rows, child rows, indexes, triggers, and mutation epochs.
- `0020-semantic-model-schema-v16.sql`: admits semantic-model schema 16 with
  exact runtime return-class sets while preserving earlier pack rows, child
  rows, indexes, triggers, and mutation epochs.
