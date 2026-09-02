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
