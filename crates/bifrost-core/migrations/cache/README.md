# Unified cache migrations

`0125-baseline.sql` is the complete cache schema and the permanent compatibility
floor. Stores below schema 125 are rebuildable derived state: startup does not
import them, and removes their database, SQLite sidecars, and analyzer-build
lock after it proves the store idle. A valid schema-125 store is upgraded.

To change the cache schema, add one numbered SQL file beginning with 0126 and
one corresponding entry to `POST_BASELINE_MIGRATIONS` in `src/cache_db.rs`.
Migration SQL must contain only schema and data changes, terminate statements
with semicolons, and omit transaction control and connection PRAGMAs. All
pending entries run in one transaction.

Regenerate and verify the baseline and forward chain with:

```console
python3 scripts/public/generate-cache-schema.py
python3 scripts/public/generate-cache-schema.py --check
```

Keep the generator's baseline and current version constants in sync with
`cache_db.rs`. Never edit a released migration and never add a down migration.
A comment-only edit to the baseline is the one exception (owner decision,
2026-09-29): SQLite keeps CREATE text verbatim, so such an edit moves
`CURRENT_SCHEMA_OBJECTS_SHA256` and nothing else; update the constant in the
same commit.

Migration `0126-policy-evaluation-per-policy.sql` replaces whole-policy-set
diff-base answers with independently qualified policy children. It discards
legacy aggregate evaluation rows because they cannot prove per-policy
completion or provenance, while preserving separately keyed policy units.

The Rust flag-day baseline also includes master's class-object and unmodeled
predicate reasons, guard-only class evidence, and C++ indirect field-binding
evidence. These are part of the single baseline, with no rehearsal migration
chain to retain.
