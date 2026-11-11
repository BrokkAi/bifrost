//! Content-based schema currency for one connection.
//!
//! SQLite rolls `schema_version` back with transactional DDL: ROLLBACK, ROLLBACK
//! TO a savepoint, and an outer ROLLBACK that undoes released TEMP savepoints all
//! restore the earlier number. Two different schemas can therefore share a
//! version on one connection, so currency checks compare schema content.
use super::cache_budget::StoreCacheBudget;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::attribution::{ConnectionTag, classifier_statements};
use brokk_bifrost_core::cache_db::sql_profile::connection_tag;
use brokk_bifrost_core::retention_budget::RetainedBytes;
use rusqlite::{Connection, MAIN_DB};
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum MainSchema {
    /// A read-only main cannot run DDL, so no rollback can repeat a version
    /// for a different main schema.
    Version(i64),
    /// A writable main can roll its own DDL back to an equal version.
    Digest([u8; 32]),
}

/// What a connection's schema was: the main schema, and the TEMP schema without
/// the rows the store's closed fixed-schema list creates lazily. Equality is
/// currency; the full TEMP digest is only a cache key and lives beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SchemaLease {
    main: MainSchema,
    temp: [u8; 32],
}

/// The closed list of lazily created fixed TEMP schemas: the two generic-formal
/// batches. The digests of the rows they produce on a scratch connection are
/// the only TEMP rows a lease ignores. A row digest covers every byte of the
/// row, so only a byte-equal row matches.
fn fixed_rows() -> &'static HashSet<[u8; 32]> {
    static ROWS: OnceLock<HashSet<[u8; 32]>> = OnceLock::new();
    ROWS.get_or_init(|| {
        let scratch = Connection::open_in_memory().expect("scratch connection");
        for batch in [
            super::resolution_stage::generic_formals_schema_sql(),
            super::resolution_stage::generic_formal_defaults_schema_sql(),
        ] {
            scratch.execute_batch(batch).expect("fixed schema applies");
        }
        scan(&scratch, "temp")
            .expect("scratch TEMP rows")
            .row_digests()
            .into_iter()
            .collect()
    })
}

/// A schema's rows, each column length-prefixed, in a fixed order, with the
/// end offset of every row.
struct Scan {
    bytes: Vec<u8>,
    row_ends: Vec<usize>,
}

impl Scan {
    fn row_digests(&self) -> Vec<[u8; 32]> {
        let mut start = 0;
        self.row_ends
            .iter()
            .map(|&end| {
                let mut hash = CanonicalHasher::new(b"bifrost-schema-lease-row:v1");
                hash.value(&self.bytes[start..end]);
                start = end;
                hash.finish()
            })
            .collect()
    }
}

fn scan(conn: &Connection, schema: &str) -> rusqlite::Result<Scan> {
    assert!(schema == "main" || schema == "temp");
    let mut statement = conn.prepare_cached(&format!(
        "SELECT type, name, tbl_name, sql FROM {schema}.sqlite_schema ORDER BY type, name"
    ))?;
    let mut rows = statement.query([])?;
    let mut scan = Scan {
        bytes: Vec::new(),
        row_ends: Vec::new(),
    };
    while let Some(row) = rows.next()? {
        for column in 0..4 {
            match row.get_ref(column)?.as_str_or_null()? {
                Some(text) => {
                    scan.bytes.push(1);
                    scan.bytes
                        .extend_from_slice(&(text.len() as u64).to_le_bytes());
                    scan.bytes.extend_from_slice(text.as_bytes());
                }
                None => scan.bytes.push(0),
            }
        }
        scan.row_ends.push(scan.bytes.len());
    }
    Ok(scan)
}

fn combine<'a>(domain: &[u8], rows: impl Iterator<Item = &'a [u8; 32]>) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(domain);
    for row in rows {
        hash.value(row);
    }
    hash.finish()
}

/// The TEMP schema a connection last showed, with its full and filtered
/// digests. A capture that scans byte-equal rows reuses the digests instead of
/// hashing the views' SQL again; the hit compares content, never a version
/// number. The entry lives in the store's cache budget, keyed by connection
/// tag. Tags are never reused, so a closed connection's entry cannot be found
/// again and is reclaimed by eviction; a missing entry costs one rehash.
pub(super) struct LastTemp {
    bytes: Vec<u8>,
    full: [u8; 32],
    filtered: [u8; 32],
}

impl RetainedBytes for LastTemp {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.bytes.capacity()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct LastTempKey(ConnectionTag);

impl RetainedBytes for LastTempKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// The full and filtered TEMP digests of `conn` now.
fn temp_digests(
    conn: &Connection,
    budget: &StoreCacheBudget,
) -> rusqlite::Result<([u8; 32], [u8; 32])> {
    let scan = scan(conn, "temp")?;
    let key = connection_tag(conn).map(LastTempKey);
    if let Some(key) = &key
        && let Some(last) = budget.last_temp_schema(key)
        && last.bytes == scan.bytes
    {
        return Ok((last.full, last.filtered));
    }
    let rows = scan.row_digests();
    let fixed = fixed_rows();
    let full = combine(b"bifrost-schema-lease-temp-full:v1", rows.iter());
    let filtered = combine(
        b"bifrost-schema-lease-temp:v1",
        rows.iter().filter(|row| !fixed.contains(*row)),
    );
    if let Some(key) = key {
        budget.insert_last_temp_schema(
            key,
            LastTemp {
                bytes: scan.bytes,
                full,
                filtered,
            },
        );
    }
    Ok((full, filtered))
}

impl SchemaLease {
    pub(crate) fn capture(conn: &Connection, budget: &StoreCacheBudget) -> rusqlite::Result<Self> {
        Ok(Self::capture_with_full_temp(conn, budget)?.0)
    }

    /// The lease and the digest of every TEMP row, from one scan. The full
    /// digest keys classification caches, which must distinguish a lazily
    /// created fixed table from its absence even though the lease does not.
    pub(super) fn capture_with_full_temp(
        conn: &Connection,
        budget: &StoreCacheBudget,
    ) -> rusqlite::Result<(Self, [u8; 32])> {
        // Schema bookkeeping, not a read of the derivation's inputs.
        let _classifier = classifier_statements();
        let main = if conn.is_readonly(MAIN_DB)? {
            MainSchema::Version(
                conn.pragma_query_value(Some("main"), "schema_version", |row| row.get(0))?,
            )
        } else {
            MainSchema::Digest(combine(
                b"bifrost-schema-lease-main:v1",
                scan(conn, "main")?.row_digests().iter(),
            ))
        };
        let (full, filtered) = temp_digests(conn, budget)?;
        Ok((
            Self {
                main,
                temp: filtered,
            },
            full,
        ))
    }

    /// True when the connection's schema is the one this lease captured. A
    /// connection that cannot be read has no schema to match.
    pub(crate) fn matches(&self, conn: &Connection, budget: &StoreCacheBudget) -> bool {
        Self::capture(conn, budget).is_ok_and(|current| current == *self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> StoreCacheBudget {
        StoreCacheBudget::new(&brokk_bifrost_core::retention_budget::RetentionBudget::for_tests())
    }

    #[test]
    fn a_cached_schema_hides_no_change_and_eviction_only_costs_a_rescan() {
        let budget = budget();
        let conn = brokk_bifrost_core::cache_db::open_in_memory_store_connection().unwrap();
        let key = LastTempKey(connection_tag(&conn).unwrap());
        conn.execute_batch("CREATE TEMP TABLE a(value)").unwrap();
        let lease = SchemaLease::capture(&conn, &budget).unwrap();
        assert!(budget.last_temp_schema(&key).is_some());
        budget.evict_classifier_regions_for_test();
        assert!(budget.last_temp_schema(&key).is_none());
        assert!(
            lease.matches(&conn, &budget),
            "an evicted entry is rescanned"
        );
        assert!(budget.last_temp_schema(&key).is_some());
        conn.execute_batch("CREATE TEMP VIEW v AS SELECT value FROM a")
            .unwrap();
        assert!(
            !lease.matches(&conn, &budget),
            "a cached schema hides no change"
        );
    }
    use rusqlite::OpenFlags;

    fn schema_version(conn: &Connection) -> i64 {
        conn.pragma_query_value(Some("main"), "schema_version", |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn a_read_only_main_cannot_run_ddl_and_leases_by_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE a(value)")
            .unwrap();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let error = conn
            .execute_batch("CREATE VIEW v AS SELECT value FROM a")
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ReadOnly)
        );
        let budget = budget();
        let lease = SchemaLease::capture(&conn, &budget).unwrap();
        assert_eq!(lease.main, MainSchema::Version(schema_version(&conn)));
        assert!(lease.matches(&conn, &budget));
    }

    #[test]
    fn a_writable_main_rolled_back_to_an_equal_version_no_longer_matches() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE a(value); CREATE TABLE b(value);")
            .unwrap();
        conn.execute_batch("BEGIN; CREATE VIEW v AS SELECT value FROM a;")
            .unwrap();
        let version = schema_version(&conn);
        let budget = budget();
        let lease = SchemaLease::capture(&conn, &budget).unwrap();
        assert!(matches!(lease.main, MainSchema::Digest(_)));
        assert!(lease.matches(&conn, &budget));
        conn.execute_batch("ROLLBACK").unwrap();
        conn.execute_batch("BEGIN; CREATE VIEW v AS SELECT value FROM b;")
            .unwrap();
        assert_eq!(schema_version(&conn), version);
        assert!(!lease.matches(&conn, &budget));
        conn.execute_batch("ROLLBACK").unwrap();
    }
}
