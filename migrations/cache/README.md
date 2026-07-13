# Unified cache migrations

`0001-current-baseline.sql` is the schema created by current Bifrost releases.
It is immutable: existing caches with `cache_state` version `1/1/10` are marked
as migration 1 without running it again.

To change the cache schema, append one `M::up(include_str!(...))` entry to
`CACHE_MIGRATIONS` in `src/cache_db.rs` and add its SQL file here. Migration SQL
must contain only schema/data changes, end statements with semicolons, and omit
transaction control and connection PRAGMAs. `rusqlite_migration` runs all pending
entries atomically and stores their count in SQLite's `user_version` header.

Never edit or add a down migration for a released file. This cache is derived
data: an older binary rejects a newer `user_version` without modifying it, while
an unrecognized pre-migration cache is rebuilt from migration 1.
