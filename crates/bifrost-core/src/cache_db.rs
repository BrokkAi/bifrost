//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
#[cfg(test)]
use rusqlite_migration::{M, Migrations};

pub type Result<T> = std::result::Result<T, String>;

/// Shared stem of every cache store file name.
const CACHE_DB_STEM: &str = "bifrost_cache";
/// The pre-versioning store name. Builds older than version-keyed naming open
/// this file in place, so a current build imports from it and never writes it.
pub const LEGACY_CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
pub const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub const LEGACY_ANALYZER_DB_FILE_NAME: &str = "analyzer_cache.db";
/// The store file and the SQLite sidecars that belong to it.
pub const STORE_FILE_SUFFIXES: [&str; 4] = ["", "-wal", "-shm", "-journal"];

const BASELINE_MIGRATION_VERSION: i64 = 1;
const CURRENT_MIGRATION_VERSION: i64 = 16;
pub const OPTIONAL_FACT_KIND_CPP_TEMPLATE_METADATA: i64 = 1;
pub const OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE: i64 = 2;
pub const OPTIONAL_FACT_KIND_SCALA_TRAIT: i64 = 3;
pub const OPTIONAL_FACT_KIND_SCALA_EXPORT: i64 = 4;
pub const OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD: i64 = 5;
const BASELINE_CACHE_STATE_VERSIONS: (i64, i64, i64) = (1, 1, 10);
const CURRENT_BASELINE_SQL: &str = include_str!("../migrations/cache/0001-current-baseline.sql");
const PATH_SYMBOL_UNITS_SQL: &str = include_str!("../migrations/cache/0002-path-symbol-units.sql");
const FORWARD_FACTS_SQL: &str = include_str!("../migrations/cache/0003-forward-facts.sql");
const ANALYZER_GENERATIONS_SQL: &str =
    include_str!("../migrations/cache/0004-analyzer-generations.sql");
const ANALYZER_BLOB_CASCADE_COSTS_SQL: &str =
    include_str!("../migrations/cache/0005-analyzer-blob-cascade-costs.sql");
const ANALYZER_BLOB_PAYLOAD_COSTS_SQL: &str =
    include_str!("../migrations/cache/0006-analyzer-blob-payload-costs.sql");
const STRUCTURAL_FACTS_SNAPSHOTS_SQL: &str =
    include_str!("../migrations/cache/0007-structural-facts-snapshots.sql");
const CPP_TEMPLATE_METADATA_SQL: &str =
    include_str!("../migrations/cache/0008-cpp-template-metadata.sql");
const SCALA_EXPORTS_SQL: &str = include_str!("../migrations/cache/0009-scala-exports.sql");
const IDENTIFIER_LOOKUP_MEMBERSHIP_SQL: &str =
    include_str!("../migrations/cache/0010-identifier-lookup-membership.sql");
const CODE_UNIT_TEST_REGION_SQL: &str =
    include_str!("../migrations/cache/0011-code-unit-test-region.sql");
const FQ_SEGMENTS_SQL: &str = include_str!("../migrations/cache/0012-fq-segments.sql");
const SEMANTIC_MODEL_ACTIVE_SET_SQL: &str =
    include_str!("../migrations/cache/0013-semantic-model-active-set.sql");
const SEMANTIC_FILE_DOCUMENTS_SQL: &str =
    include_str!("../migrations/cache/0014-semantic-file-documents.sql");
const MATERIALIZATION_RECORDS_SQL: &str =
    include_str!("../migrations/cache/0015-materialization-records.sql");
const OPTIONAL_FACT_MANIFEST_SQL: &str =
    include_str!("../migrations/cache/0016-optional-fact-manifest.sql");
const CACHE_MIGRATION_SQL: [&str; CURRENT_MIGRATION_VERSION as usize] = [
    CURRENT_BASELINE_SQL,
    PATH_SYMBOL_UNITS_SQL,
    FORWARD_FACTS_SQL,
    ANALYZER_GENERATIONS_SQL,
    ANALYZER_BLOB_CASCADE_COSTS_SQL,
    ANALYZER_BLOB_PAYLOAD_COSTS_SQL,
    STRUCTURAL_FACTS_SNAPSHOTS_SQL,
    CPP_TEMPLATE_METADATA_SQL,
    SCALA_EXPORTS_SQL,
    IDENTIFIER_LOOKUP_MEMBERSHIP_SQL,
    CODE_UNIT_TEST_REGION_SQL,
    FQ_SEGMENTS_SQL,
    SEMANTIC_MODEL_ACTIVE_SET_SQL,
    SEMANTIC_FILE_DOCUMENTS_SQL,
    MATERIALIZATION_RECORDS_SQL,
    OPTIONAL_FACT_MANIFEST_SQL,
];
// The store file is named for the schema version that wrote it, and that
// version is the migration count. Tie the two at compile time so a migration
// added without touching `CURRENT_MIGRATION_VERSION` cannot ship a file name
// that lies about its schema.
const _: () = assert!(CACHE_MIGRATION_SQL.len() == CURRENT_MIGRATION_VERSION as usize);
static CACHE_DB_FILE_NAME: Lazy<String> =
    Lazy::new(|| cache_db_file_name_for_version(CURRENT_MIGRATION_VERSION));
#[cfg(test)]
static CACHE_MIGRATIONS: Lazy<Migrations<'static>> =
    Lazy::new(|| Migrations::new(CACHE_MIGRATION_SQL.into_iter().map(M::up).collect()));
static BASELINE_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open baseline schema connection");
    conn.execute_batch(CURRENT_BASELINE_SQL)
        .expect("create baseline schema");
    schema_object_definitions(&conn).expect("read baseline schema definitions")
});
#[cfg(test)]
static CURRENT_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open current schema connection");
    conn.execute_batch(CURRENT_BASELINE_SQL)
        .expect("create baseline schema");
    conn.execute_batch(PATH_SYMBOL_UNITS_SQL)
        .expect("apply path symbol migration");
    conn.execute_batch(FORWARD_FACTS_SQL)
        .expect("apply forward facts migration");
    conn.execute_batch(ANALYZER_GENERATIONS_SQL)
        .expect("apply analyzer generations migration");
    conn.execute_batch(ANALYZER_BLOB_CASCADE_COSTS_SQL)
        .expect("apply analyzer blob cascade costs migration");
    conn.execute_batch(ANALYZER_BLOB_PAYLOAD_COSTS_SQL)
        .expect("apply analyzer blob payload costs migration");
    conn.execute_batch(STRUCTURAL_FACTS_SNAPSHOTS_SQL)
        .expect("apply structural facts snapshots migration");
    conn.execute_batch(CPP_TEMPLATE_METADATA_SQL)
        .expect("apply C++ template metadata migration");
    conn.execute_batch(SCALA_EXPORTS_SQL)
        .expect("apply Scala exports migration");
    conn.execute_batch(IDENTIFIER_LOOKUP_MEMBERSHIP_SQL)
        .expect("apply identifier lookup membership migration");
    conn.execute_batch(CODE_UNIT_TEST_REGION_SQL)
        .expect("apply code unit test region migration");
    conn.execute_batch(FQ_SEGMENTS_SQL)
        .expect("apply fq segments migration");
    conn.execute_batch(SEMANTIC_MODEL_ACTIVE_SET_SQL)
        .expect("apply semantic model active set migration");
    conn.execute_batch(SEMANTIC_FILE_DOCUMENTS_SQL)
        .expect("apply semantic file documents migration");
    conn.execute_batch(MATERIALIZATION_RECORDS_SQL)
        .expect("apply materialization records migration");
    conn.execute_batch(OPTIONAL_FACT_MANIFEST_SQL)
        .expect("apply optional fact manifest migration");
    schema_object_definitions(&conn).expect("read current schema definitions")
});
pub const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);
// One primary-repository cache is intentionally shared by every linked worktree.
// Large repositories can therefore have several independent analyzer/semantic
// processes queue behind one legitimate writer during evaluation or IDE fanout.
// Five seconds was shorter than observed write transactions and converted
// ordinary serialization into a permanently failed semantic index. Keep SQLite
// as the cross-process arbiter, but give queued writers enough time to take their
// turn instead of requiring per-worktree database copies.
const BUSY_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-connection prepared-statement cache capacity. rusqlite defaults to 16,
/// which is far too small for our query surface: `format!`-spliced predicates
/// and (now fixed-arity) `IN` lists produce dozens of distinct SQL shapes, and
/// a 16-slot cache thrashes, re-preparing/finalizing hot statements inside the
/// critical section. 64 covers the observed shape count with headroom.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 64;
const INITIALIZATION_RETRY_DEADLINE: Duration = BUSY_TIMEOUT;
const INITIALIZATION_RETRY_BACKOFF: Duration = Duration::from_millis(5);
const INITIALIZATION_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(100);
const GENERATED_CACHE_GITIGNORE: &[u8] = b"*\n";
const GENERATED_LEGACY_PROJECT_GITIGNORE: &[u8] = b"/.gitignore\n/bifrost_cache.db\n/bifrost_cache.db-wal\n/bifrost_cache.db-shm\n/bifrost_cache.db-journal\n";
// Persistent pragma setup and migration are serialized only among same-process
// openers for one canonical cache path. SQLite remains the cross-process lock.
static PROCESS_LOCAL_OPEN_GUARDS: Lazy<Mutex<std::collections::HashMap<PathBuf, Weak<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
static PROCESS_LOCAL_VERSION_SWEEP_ATTEMPTS: Lazy<Mutex<HashSet<PathBuf>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// How long a store from another schema version must go untouched before
/// collection removes it.
pub const VERSION_STORE_GRACE_SECS: i64 = 14 * 24 * 3600;
/// The store file this build owns: `bifrost_cache.v{schema version}.db`.
///
/// The schema version belongs in the name rather than only in the file's
/// `user_version`. A single shared file migrates in place, so the newest build
/// to touch it decides for every checkout of the repository, and older builds
/// then refuse the whole file (issue #1589). Naming the file by its schema
/// instead lets versions sit side by side: each build opens exactly its own,
/// and the row-level design already keys rather than migrates everything else.
pub fn cache_db_file_name() -> &'static str {
    &CACHE_DB_FILE_NAME
}

/// The store file name for an arbitrary schema `version`.
pub fn cache_db_file_name_for_version(version: i64) -> String {
    format!("{CACHE_DB_STEM}.v{version}.db")
}

/// The schema version this build reads and writes.
pub fn cache_db_schema_version() -> i64 {
    CURRENT_MIGRATION_VERSION
}

/// The schema version a store file name declares, or `None` when the name is
/// not one this scheme owns.
///
/// Deliberately strict: the cache directory also holds sidecars, hand-made
/// backups such as `bifrost_cache.db.schema14.bak`, and the legacy
/// unversioned store. None of those are candidates for import or collection,
/// and a loose match would put a developer's backup in reach of the sweeper.
pub fn store_file_version(name: &str) -> Option<i64> {
    let digits = name
        .strip_prefix(CACHE_DB_STEM)?
        .strip_prefix(".v")?
        .strip_suffix(".db")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `store` with `suffix` appended to its file name, for the SQLite sidecars in
/// [`STORE_FILE_SUFFIXES`].
pub fn store_file_with_suffix(store: &Path, suffix: &str) -> PathBuf {
    let mut name = store
        .file_name()
        .expect("a cache store path has a file name")
        .to_os_string();
    name.push(suffix);
    store.with_file_name(name)
}

/// Remove versioned stores that have not been used during the grace period.
///
/// Only older stores are candidates. The current store and stores from a
/// newer build remain available to older or newer checkouts. The newest mtime
/// across the store and its sidecars represents use because WAL activity may
/// not update the main database file.
pub fn sweep_disused_version_stores(cache_dir: &Path) -> Result<Vec<PathBuf>> {
    let stores = disused_version_store_paths(cache_dir)?;
    remove_version_stores(&stores)?;
    Ok(stores)
}

fn disused_version_store_paths(cache_dir: &Path) -> Result<Vec<PathBuf>> {
    let now = now_unix_seconds();
    let mut stores = Vec::new();
    for entry in std::fs::read_dir(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))? {
        let entry = entry.map_err(|err| format!("cache DB I/O error: {err}"))?;
        let name = entry.file_name();
        let Some(version) = name.to_str().and_then(store_file_version) else {
            continue;
        };
        if version >= cache_db_schema_version() {
            continue;
        }
        let store = entry.path();
        if last_store_use_unix_seconds(&store)? + VERSION_STORE_GRACE_SECS > now {
            continue;
        }
        stores.push(store);
    }
    Ok(stores)
}

fn remove_version_stores(stores: &[PathBuf]) -> Result<()> {
    for store in stores {
        for suffix in STORE_FILE_SUFFIXES {
            let path = store_file_with_suffix(store, suffix);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "cache DB I/O error removing {}: {err}",
                        path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn last_store_use_unix_seconds(store: &Path) -> Result<i64> {
    let mut newest = 0;
    for suffix in STORE_FILE_SUFFIXES {
        let path = store_file_with_suffix(store, suffix);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "cache DB I/O error reading {}: {err}",
                    path.display()
                ));
            }
        };
        let modified = metadata
            .modified()
            .map_err(|err| format!("cache DB I/O error reading {}: {err}", path.display()))?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|delta| delta.as_secs() as i64)
            .unwrap_or(0);
        newest = newest.max(modified);
    }
    Ok(newest)
}

/// Open the workspace's shared cache database, creating it if necessary.
///
/// The database is at the *primary* repository root (`gitblob::cache_db_path`),
/// so every linked worktree of a checkout writes the same oid-keyed file. A
/// process that cannot write there is misconfigured rather than out of options,
/// so a permission denial is reported with the ways out instead of SQLite's
/// bare `unable to open database file` (issue #1544).
pub fn open_unified_connection(db_path: &Path) -> Result<Connection> {
    open_unified_connection_unclassified(db_path).map_err(|error| {
        match cache_write_denial(db_path) {
            Some(denied) => cache_permission_denied_message(db_path, &denied),
            None => error,
        }
    })
}

/// The path the process cannot write, when a cache open failed on filesystem
/// permissions.
///
/// A denial reaches [`open_unified_connection`] in three different shapes --
/// `EACCES` from creating `.bifrost/cache`, `EACCES` from staging the
/// directory's `.gitignore`, and SQLite's cause-free `SQLITE_CANTOPEN` when the
/// directory exists but the database cannot be created in it -- so ask the
/// filesystem directly rather than interpreting any of the three messages.
/// Only ever called on an already-failed open.
fn cache_write_denial(db_path: &Path) -> Option<PathBuf> {
    if db_path.is_file()
        && let Err(error) = std::fs::OpenOptions::new().write(true).open(db_path)
        && error.kind() == std::io::ErrorKind::PermissionDenied
    {
        return Some(db_path.to_path_buf());
    }
    let existing_ancestor = db_path.ancestors().skip(1).find(|path| path.is_dir())?;
    match tempfile::NamedTempFile::new_in(existing_ancestor) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Some(existing_ancestor.to_path_buf())
        }
        _ => None,
    }
}

/// Report a cache-write denial with its exits ordered by how well they preserve
/// the shared cache. `BIFROST_CACHE_DIR` comes last on purpose: it re-creates
/// exactly the per-root divergence issue #1544 removed.
fn cache_permission_denied_message(db_path: &Path, denied: &Path) -> String {
    format!(
        "cannot write the Bifrost analyzer cache {}: permission denied for {}.\n\
         The cache lives at the primary repository root, beside the Git object database the \
         analyzer must already read, and every linked worktree shares it.\n\
         1. Re-run with approved or elevated filesystem permissions for {}. In a sandboxed \
         shell this is the same escalation that writing `.git` needs.\n\
         2. If this run is deliberately transient, point BIFROST_CACHE_DIR at a throwaway \
         directory (`mktemp -d`) and delete it afterwards; nothing outlives the run.\n\
         3. Last resort: set BIFROST_CACHE_DIR=<writable dir> to relocate the cache. WARNING: \
         that cache is separate, so it neither benefits from nor contributes to the shared \
         one; every workspace using it re-extracts everything and the two drift apart. This is \
         usually the wrong choice.",
        db_path.display(),
        denied.display(),
        denied.display(),
    )
}

fn open_unified_connection_unclassified(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    // Project-layout preparation can migrate the tracked `.bifrost/.gitignore`.
    // Serialize it separately from the database open: the cache directory may
    // not exist yet, so `prepare_cache_db_path` must run before we can derive
    // the canonical database key used by the SQLite initialization lock below.
    // Canonicalizing the existing project directory also makes equivalent
    // spellings of the default cache path share the same preparation lock.
    let preparation_key = default_project_dir_for_cache(db_path)
        .and_then(|project_dir| project_dir.canonicalize().ok())
        .unwrap_or_else(|| db_path.to_path_buf());
    let process_local_preparation_lock = process_local_open_lock_cell(&preparation_key)?;
    let db_path = {
        let _process_local_preparation_guard =
            process_local_preparation_lock.lock().map_err(|_| {
                format!(
                    "cache DB process-local preparation guard poisoned for {}",
                    db_path.display()
                )
            })?;
        prepare_cache_db_path(db_path)?
    };
    ensure_safe_cache_path(&db_path)?;
    let process_local_open_lock = process_local_open_lock_cell(&db_path)?;
    let _process_local_open_guard = process_local_open_lock.lock().map_err(|_| {
        format!(
            "cache DB process-local open guard poisoned for {}",
            db_path.display()
        )
    })?;
    let startup_cleanup = disused_version_stores_on_startup(&db_path);
    import_newest_older_store(&db_path)?;
    let mut conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_connection_after_busy_timeout(&mut conn)?;
    let initialized_before_open = unified_cache_initialized(&conn)?;
    migrate(&mut conn)?;
    if !initialized_before_open {
        delete_legacy_cache_files(&db_path);
    }
    if let Some(stores) = startup_cleanup
        && let Err(error) = remove_version_stores(&stores)
    {
        eprintln!("Bifrost cache startup cleanup skipped: {error}");
    }
    Ok(conn)
}

fn disused_version_stores_on_startup(db_path: &Path) -> Option<Vec<PathBuf>> {
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return None;
    }
    let cache_dir = db_path.parent()?;
    let should_attempt = PROCESS_LOCAL_VERSION_SWEEP_ATTEMPTS
        .lock()
        .expect("cache version sweep mutex poisoned")
        .insert(cache_dir.to_path_buf());
    if !should_attempt {
        return None;
    }
    match disused_version_store_paths(cache_dir) {
        Ok(stores) => Some(stores),
        Err(error) => {
            // Old stores are optional cache data. An unreadable old store must
            // not prevent the current store from opening. A later process can
            // retry the sweep.
            eprintln!("Bifrost cache startup cleanup skipped: {error}");
            None
        }
    }
}

/// Open a read-only connection to an already-initialized cache DB.
///
/// The writer connection (`open_unified_connection`) is responsible for
/// creating the file, running migrations, and establishing WAL mode — all of
/// which are persistent database properties. A reader therefore opens with
/// `SQLITE_OPEN_READ_ONLY` (making "a reader cannot write" a hard, SQLite-level
/// invariant) and applies only the read-relevant pragmas. Under WAL a read-only
/// connection still reads the writer's committed snapshots as long as the
/// process can access the `-wal`/`-shm` sidecars, which it can: the same process
/// created the DB and holds the writer open for the store's lifetime.
pub fn open_readonly_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_readonly_connection(&conn)?;
    Ok(conn)
}

/// Open an initialized cache with a read-only main database and a writable
/// temporary schema.
///
/// Active semantic-search state belongs to one worktree. It must not enter the
/// shared cache. The SQLite read-only flag prevents persistent writes, while a
/// writable TEMP schema permits connection-local membership and FTS tables.
pub fn open_readonly_temp_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB active-session SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_readonly_page_cache(&conn)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB active-session SQLite error: {err}"))?;
    Ok(conn)
}

/// Open a read-only connection for a broad, disposable analyzer scan.
///
/// Streaming readers deliberately retain little SQLite state: unlike an
/// interactive reader, a sequential workspace scan is unlikely to reuse pages
/// after advancing to the next file group. Keeping these connections separate
/// prevents their page cache and mmap residency from displacing interactive
/// analyzer queries.
pub fn open_streaming_readonly_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB streaming read-only SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB streaming read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", -2048)
        .map_err(|err| format!("cache DB streaming read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 0)
        .map_err(|err| format!("cache DB streaming read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "query_only", "ON")
        .map_err(|err| format!("cache DB streaming read-only SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(conn)
}

fn canonicalize_cache_db_parent(db_path: &Path) -> Result<PathBuf> {
    let parent = db_path
        .parent()
        .ok_or_else(|| format!("cache DB path has no parent: {}", db_path.display()))?;
    let file_name = db_path
        .file_name()
        .ok_or_else(|| format!("cache DB path has no file name: {}", db_path.display()))?;
    let parent = parent
        .canonicalize()
        .map_err(|err| format!("cache DB I/O error: {err}"))?;
    Ok(parent.join(file_name))
}

/// Apply the pragmas that matter for a read-only WAL connection. Deliberately
/// omits every write/schema-mutating pragma the writer path runs
/// (`journal_mode`, `auto_vacuum`, `foreign_keys`, `wal_autocheckpoint`,
/// `synchronous`, …): those are either persistent file properties already
/// established by the writer or illegal to set on a read-only handle.
fn configure_readonly_connection(conn: &Connection) -> Result<()> {
    configure_readonly_page_cache(conn)?;
    conn.pragma_update(None, "query_only", "ON")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    Ok(())
}

fn configure_readonly_page_cache(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", -65536)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

fn unified_cache_initialized(conn: &Connection) -> Result<bool> {
    let has_cache_state: bool = conn
        .query_row(
            "SELECT EXISTS(
           SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'cache_state'
         )",
            [],
            |row| row.get(0),
        )
        .map_err(|err| format!("cache DB initialization-state query SQLite error: {err}"))?;
    if !has_cache_state {
        return Ok(false);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM cache_state WHERE id = 1)",
        [],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB initialization-state query SQLite error: {err}"))
}

fn prepare_cache_db_path(db_path: &Path) -> Result<PathBuf> {
    if let Some(project_dir) = default_project_dir_for_cache(db_path) {
        migrate_legacy_project_cache(project_dir)?;
    }
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("cache DB I/O error: {err}"))?;
        ensure_cache_dir_self_ignored(parent)?;
        if let Some(file_name) = db_path.file_name() {
            let parent = parent
                .canonicalize()
                .map_err(|err| format!("cache DB I/O error: {err}"))?;
            return Ok(parent.join(file_name));
        }
    }
    Ok(db_path.to_path_buf())
}

/// Seed this build's store from the newest older one, when it has none yet.
///
/// Version-keyed naming means an upgrade lands on a file that does not exist,
/// which would otherwise mean a cold start for a corpus that is already
/// extracted. Copy the newest store this build can migrate forward instead and
/// let [`migrate`] carry the copy the rest of the way. The source is only ever
/// read: an older checkout keeps opening it, and the existence of a newer file
/// says nothing about whether the older one is still live (issue #1589).
///
/// The copy goes through SQLite's backup API rather than the filesystem
/// because a live source holds committed pages in its `-wal` sidecar; copying
/// the main file alone would silently drop them.
fn import_newest_older_store(db_path: &Path) -> Result<()> {
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return Ok(());
    }
    if db_path.exists() {
        return Ok(());
    }
    let cache_dir = db_path
        .parent()
        .expect("a prepared cache DB path has a parent directory");
    let Some(source) = newest_importable_store(cache_dir)? else {
        return Ok(());
    };
    let source_conn = Connection::open_with_flags(
        &source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| {
        format!(
            "cache DB import SQLite error reading {}: {err}",
            source.display()
        )
    })?;
    let staged = tempfile::Builder::new()
        .prefix(".bifrost-cache-import")
        .tempfile_in(cache_dir)
        .map_err(|err| format!("failed to stage cache DB import: {err}"))?;
    source_conn
        .backup(rusqlite::DatabaseName::Main, staged.path(), None)
        .map_err(|err| {
            format!(
                "cache DB import SQLite error copying {}: {err}",
                source.display()
            )
        })?;
    match staged.persist_noclobber(db_path) {
        Ok(_) => Ok(()),
        // Another process published its own import first. It drew from the same
        // candidate set, so ours has nothing to add.
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(format!(
            "failed to atomically publish imported cache DB {}: {}",
            db_path.display(),
            err.error
        )),
    }
}

/// The newest store in `cache_dir` this build can migrate forward.
///
/// Candidates are the version-suffixed stores older than this build's, plus
/// the pre-versioning `bifrost_cache.db`. The legacy file carries no version
/// in its name, so its `user_version` decides: one written by a newer build
/// cannot be dragged backwards and is skipped. Everything else in the
/// directory -- a hand-made backup, another tool's database -- is not ours.
fn newest_importable_store(cache_dir: &Path) -> Result<Option<PathBuf>> {
    let mut newest: Option<(i64, PathBuf)> = None;
    for entry in std::fs::read_dir(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))? {
        let entry = entry.map_err(|err| format!("cache DB I/O error: {err}"))?;
        let name = entry.file_name();
        let Some(version) = name.to_str().and_then(store_file_version) else {
            continue;
        };
        if version >= CURRENT_MIGRATION_VERSION {
            continue;
        }
        if newest
            .as_ref()
            .is_none_or(|(newest_version, _)| version > *newest_version)
        {
            newest = Some((version, entry.path()));
        }
    }

    let legacy = cache_dir.join(LEGACY_CACHE_DB_FILE_NAME);
    if legacy.is_file() {
        let legacy_version = store_user_version(&legacy)?;
        if legacy_version <= CURRENT_MIGRATION_VERSION
            && newest
                .as_ref()
                .is_none_or(|(newest_version, _)| legacy_version > *newest_version)
        {
            newest = Some((legacy_version, legacy));
        }
    }
    Ok(newest.map(|(_, path)| path))
}

fn store_user_version(path: &Path) -> Result<i64> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB SQLite error reading {}: {err}", path.display()))?;
    cache_migration_version(&conn)
}

fn default_project_dir_for_cache(db_path: &Path) -> Option<&Path> {
    let explicit_override = std::env::var_os(crate::gitblob::CACHE_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|cache_dir| cache_dir.join(cache_db_file_name()));
    default_project_dir_for_cache_with_override(db_path, explicit_override.as_deref())
}

fn default_project_dir_for_cache_with_override<'a>(
    db_path: &'a Path,
    explicit_override: Option<&Path>,
) -> Option<&'a Path> {
    if explicit_override == Some(db_path) {
        return None;
    }
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return None;
    }
    let cache_dir = db_path.parent()?;
    if cache_dir.file_name() != Some(std::ffi::OsStr::new(crate::gitblob::CACHE_SUBDIR_NAME)) {
        return None;
    }
    let project_dir = cache_dir.parent()?;
    (project_dir.file_name() == Some(std::ffi::OsStr::new(crate::gitblob::PROJECT_DIR_NAME)))
        .then_some(project_dir)
}

fn migrate_legacy_project_cache(project_dir: &Path) -> Result<()> {
    let project_dir = match project_dir.canonicalize() {
        Ok(project_dir) => project_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cache DB I/O error: {err}")),
    };
    let has_legacy_state = validate_legacy_project_cache_state(&project_dir)?;
    let ignore_path = project_dir.join(".gitignore");
    let metadata = match std::fs::symlink_metadata(&ignore_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return if has_legacy_state {
                create_legacy_project_cache_ignore(&ignore_path)
            } else {
                Ok(())
            };
        }
        Err(err) => return Err(format!("cache DB I/O error: {err}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "refusing to migrate legacy cache ignore that is not a regular file: {}",
            ignore_path.display()
        ));
    }
    let content =
        std::fs::read(&ignore_path).map_err(|err| format!("cache DB I/O error: {err}"))?;
    if content == GENERATED_CACHE_GITIGNORE {
        // Never unlink the old database automatically. An older Bifrost process
        // can reopen the legacy path after any SQLite idleness check, so deleting
        // it and its sidecars would race a live writer. Narrow the exact generated
        // whole-directory ignore to the exact legacy filenames instead. The
        // compatibility ignore also ignores itself, leaving project-owned
        // `.bifrost` configuration visible without creating untracked noise.
        return replace_generated_legacy_project_ignore(&ignore_path);
    }
    if content != GENERATED_LEGACY_PROJECT_GITIGNORE {
        if gitignore_ignores_entire_directory(&content) {
            return Err(format!(
                "legacy {} still ignores all tracked .bifrost configuration; replace the whole-directory rule with cache/",
                ignore_path.display()
            ));
        }
        if has_legacy_state {
            return Err(format!(
                "legacy cache state beside tracked .bifrost configuration is not covered by the user-authored {}; stop older Bifrost processes, remove the legacy bifrost_cache.db files, or add exact ignore rules",
                ignore_path.display()
            ));
        }
        return Ok(());
    }
    Ok(())
}

fn create_legacy_project_cache_ignore(ignore_path: &Path) -> Result<()> {
    let parent = ignore_path.parent().ok_or_else(|| {
        format!(
            "legacy cache ignore has no parent directory: {}",
            ignore_path.display()
        )
    })?;
    let mut replacement = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to stage legacy cache ignore: {err}"))?;
    replacement
        .write_all(GENERATED_LEGACY_PROJECT_GITIGNORE)
        .and_then(|()| replacement.as_file().sync_all())
        .map_err(|err| format!("failed to stage legacy cache ignore: {err}"))?;
    match replacement.persist_noclobber(ignore_path) {
        Ok(_) => Ok(()),
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_concurrent_legacy_project_ignore(ignore_path)
        }
        Err(err) => Err(format!(
            "failed to atomically publish legacy cache ignore {}: {}",
            ignore_path.display(),
            err.error
        )),
    }
}

fn replace_generated_legacy_project_ignore(ignore_path: &Path) -> Result<()> {
    let parent = ignore_path.parent().ok_or_else(|| {
        format!(
            "legacy cache ignore has no parent directory: {}",
            ignore_path.display()
        )
    })?;
    let mut replacement = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to stage narrowed legacy cache ignore: {err}"))?;
    replacement
        .write_all(GENERATED_LEGACY_PROJECT_GITIGNORE)
        .and_then(|()| replacement.as_file().sync_all())
        .map_err(|err| format!("failed to stage narrowed legacy cache ignore: {err}"))?;
    replacement.persist(ignore_path).map_err(|err| {
        format!(
            "failed to atomically narrow generated legacy cache ignore {}: {}",
            ignore_path.display(),
            err.error
        )
    })?;
    Ok(())
}

fn validate_concurrent_legacy_project_ignore(ignore_path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(ignore_path)
        .map_err(|err| format!("cache DB I/O error: {err}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "legacy cache ignore created concurrently is not a regular file: {}",
            ignore_path.display()
        ));
    }
    let content = std::fs::read(ignore_path).map_err(|err| format!("cache DB I/O error: {err}"))?;
    if content == GENERATED_LEGACY_PROJECT_GITIGNORE {
        Ok(())
    } else if content == GENERATED_CACHE_GITIGNORE {
        replace_generated_legacy_project_ignore(ignore_path)
    } else {
        Err(format!(
            "legacy cache ignore changed while it was being migrated: {}",
            ignore_path.display()
        ))
    }
}

fn gitignore_ignores_entire_directory(content: &[u8]) -> bool {
    String::from_utf8_lossy(content)
        .lines()
        .any(|line| matches!(line.trim(), "*" | "/*" | "**" | "/**"))
}

fn cache_gitignore_ignores_all_generated_state(content: &[u8]) -> bool {
    let mut ignores_all = false;
    for line in String::from_utf8_lossy(content).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('!') {
            return false;
        }
        ignores_all |= matches!(line, "*" | "/*" | "**" | "/**");
    }
    ignores_all
}

fn validate_legacy_project_cache_state(project_dir: &Path) -> Result<bool> {
    let legacy = project_dir.join(LEGACY_CACHE_DB_FILE_NAME);
    let mut found = false;
    for suffix in STORE_FILE_SUFFIXES {
        let path = store_file_with_suffix(&legacy, suffix);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(format!(
                    "refusing legacy cache state that is not a regular file: {}",
                    path.display()
                ));
            }
            Ok(_) => found = true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("cache DB I/O error: {err}")),
        }
    }
    Ok(found)
}

pub fn is_legacy_project_cache_file_name(name: &std::ffi::OsStr) -> bool {
    STORE_FILE_SUFFIXES
        .iter()
        .any(|suffix| name == std::ffi::OsStr::new(&format!("{LEGACY_CACHE_DB_FILE_NAME}{suffix}")))
}

/// Make the generated cache directory ignore itself, the way `cargo` does for `target/`.
///
/// The unified SQLite cache lives at the primary repository root
/// (`<primary>/.bifrost/cache/`, shared by every linked worktree of that
/// checkout; a root outside any repository keeps its own), so its database plus
/// the WAL and shared-memory sidecars are live, continuously rewritten files
/// sitting in a working tree. Anything that walks the tree
/// through git therefore sees them, and anything that walks it while the cache
/// is being written can observe a file mutating mid-read: `analyze_diff` asks
/// libgit2 for untracked *content* (`show_untracked_content`), so it would try
/// to read `bifrost_cache.db-wal` as if it were a source hunk and fail the whole
/// request with `file changed before we could read it; class=Filesystem (30)`.
///
/// Writing `.gitignore` containing `*` into the cache directory removes the
/// whole class of problem at its source rather than per-consumer: git and
/// libgit2 then treat the directory as ignored, and every tree walk skips it
/// (diff already excludes ignored entries), as does `git status` for users.
/// `project_watcher` had to special-case this same directory for the same
/// underlying reason; this keeps the next such surface from needing one.
///
/// Existing safe content is left untouched so repeated opens neither rewrite it
/// nor churn its mtime. An existing file that does not ignore the generated
/// directory is an error rather than a silent source of live SQLite files.
fn ensure_cache_dir_self_ignored(cache_dir: &Path) -> Result<()> {
    if default_project_dir_for_cache(&cache_dir.join(cache_db_file_name())).is_none() {
        return Ok(());
    }
    let ignore_path = cache_dir.join(".gitignore");
    match std::fs::symlink_metadata(&ignore_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(format!(
                "cache directory ignore is not a regular file: {}",
                ignore_path.display()
            ));
        }
        Ok(_) => return validate_cache_gitignore(&ignore_path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("cache DB I/O error: {err}")),
    }
    let mut replacement = tempfile::NamedTempFile::new_in(cache_dir)
        .map_err(|err| format!("failed to stage cache directory ignore: {err}"))?;
    replacement
        .write_all(GENERATED_CACHE_GITIGNORE)
        .and_then(|()| replacement.as_file().sync_all())
        .map_err(|err| format!("failed to stage cache directory ignore: {err}"))?;
    match replacement.persist_noclobber(&ignore_path) {
        Ok(_) => Ok(()),
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_cache_gitignore(&ignore_path)
        }
        Err(err) => Err(format!(
            "failed to atomically publish cache directory ignore {}: {}",
            ignore_path.display(),
            err.error
        )),
    }
}

fn validate_cache_gitignore(ignore_path: &Path) -> Result<()> {
    let content = std::fs::read(ignore_path).map_err(|err| format!("cache DB I/O error: {err}"))?;
    if cache_gitignore_ignores_all_generated_state(&content) {
        Ok(())
    } else {
        Err(format!(
            "cache directory ignore does not ignore generated state: {}",
            ignore_path.display()
        ))
    }
}

fn process_local_open_lock_cell(db_path: &Path) -> Result<Arc<Mutex<()>>> {
    let mut guards = PROCESS_LOCAL_OPEN_GUARDS
        .lock()
        .map_err(|_| "cache DB process-local open guard mutex poisoned".to_string())?;
    guards.retain(|_, cell| cell.strong_count() > 0);
    if let Some(lock) = guards.get(db_path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    guards.insert(db_path.to_path_buf(), Arc::downgrade(&lock));
    Ok(lock)
}

pub fn configure_connection(conn: &mut Connection) -> Result<()> {
    install_busy_timeout(conn)?;
    configure_connection_after_busy_timeout(conn)
}

fn install_busy_timeout(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(|err| format!("cache DB busy-timeout configuration SQLite error: {err}"))
}

fn configure_connection_after_busy_timeout(conn: &mut Connection) -> Result<()> {
    if conn.path().is_some_and(|path| !path.is_empty()) {
        retry_initialization_phase("auto-vacuum initialization", || {
            ensure_incremental_auto_vacuum(conn)
        })?;
        retry_initialization_phase("journal-mode initialization", || {
            ensure_wal_journal_mode(conn)
        })?;
    }
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "ignore_check_constraints", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "recursive_triggers", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", -65536)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "wal_autocheckpoint", 2000)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

enum InitializationPhaseError {
    Sqlite(rusqlite::Error),
    Verification(String),
}

impl From<rusqlite::Error> for InitializationPhaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

fn ensure_wal_journal_mode(conn: &Connection) -> std::result::Result<(), InitializationPhaseError> {
    let current: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if current.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    let updated: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if updated.eq_ignore_ascii_case("wal") {
        Ok(())
    } else {
        Err(InitializationPhaseError::Verification(format!(
            "requested WAL but SQLite reported {updated}"
        )))
    }
}

fn ensure_incremental_auto_vacuum(
    conn: &Connection,
) -> std::result::Result<(), InitializationPhaseError> {
    let current: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if current == 2 {
        return Ok(());
    }
    let schema_is_empty: bool = conn.query_row(
        "SELECT NOT EXISTS(
           SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?;
    // SQLite cannot change a populated mode-0 database without VACUUM. Cache
    // compatibility wins over an implicit full rewrite; existing databases keep
    // their current mode, while fresh databases are configured before migration.
    if current == 0 && !schema_is_empty {
        return Ok(());
    }
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    let updated: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if updated == 2 {
        Ok(())
    } else {
        Err(InitializationPhaseError::Verification(format!(
            "requested INCREMENTAL (2) but SQLite reported {updated}"
        )))
    }
}

fn retry_initialization_phase<T>(
    phase: &str,
    operation: impl FnMut() -> std::result::Result<T, InitializationPhaseError>,
) -> Result<T> {
    retry_initialization_phase_with(
        phase,
        INITIALIZATION_RETRY_DEADLINE,
        std::thread::sleep,
        operation,
    )
}

fn retry_initialization_phase_with<T>(
    phase: &str,
    deadline: Duration,
    mut sleep: impl FnMut(Duration),
    mut operation: impl FnMut() -> std::result::Result<T, InitializationPhaseError>,
) -> Result<T> {
    let started = Instant::now();
    let mut backoff = INITIALIZATION_RETRY_BACKOFF;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(InitializationPhaseError::Sqlite(error))
                if error.sqlite_error_code() == Some(ErrorCode::DatabaseBusy) =>
            {
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return Err(format!(
                        "cache DB {phase} timed out after {elapsed:?}: {error}"
                    ));
                }
                sleep(backoff.min(deadline.saturating_sub(elapsed)));
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return Err(format!(
                        "cache DB {phase} timed out after {elapsed:?}: {error}"
                    ));
                }
                backoff = backoff
                    .saturating_mul(2)
                    .min(INITIALIZATION_RETRY_MAX_BACKOFF);
            }
            Err(InitializationPhaseError::Sqlite(error)) => {
                return Err(format!("cache DB {phase} SQLite error: {error}"));
            }
            Err(InitializationPhaseError::Verification(error)) => {
                return Err(format!("cache DB {phase} verification failed: {error}"));
            }
        }
    }
}

fn ensure_safe_cache_path(db_path: &Path) -> Result<()> {
    if let Some(project_dir) = default_project_dir_for_cache(db_path) {
        reject_symlink(project_dir, "Bifrost project directory")?;
    }
    let Some(parent) = db_path.parent() else {
        return Ok(());
    };
    reject_symlink(parent, "cache directory")?;
    reject_symlink(db_path, "cache database")?;
    reject_symlink(&db_path.with_extension("db-wal"), "cache WAL")?;
    reject_symlink(&db_path.with_extension("db-shm"), "cache SHM")?;
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing to use {label} symlink {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("cache DB I/O error: {err}")),
    }
}

pub fn migrate(conn: &mut Connection) -> Result<()> {
    assert_sqlite_version(conn)?;
    migrate_with_sql(conn, &CACHE_MIGRATION_SQL)
}

fn migrate_with_sql(conn: &mut Connection, migrations: &[&str]) -> Result<()> {
    let user_version = cache_migration_version(conn)?;
    if current_schema_fast_path(migrations, user_version) {
        return Ok(());
    }
    // Ordinary migrations keep FK enforcement enabled because their DELETEs rely on
    // cascades. Rebuilding an invalid schema needs it disabled, but SQLite cannot
    // change foreign_keys inside a transaction. The first locked pass makes no
    // changes when it detects that case; after toggling, the repair pass reacquires
    // the write lock and re-inspects before rebuilding and migrating atomically.
    if matches!(
        migrate_with_sql_locked(conn, migrations, false)?,
        LockedMigrationOutcome::Complete
    ) {
        return Ok(());
    }

    conn.pragma_update(None, "foreign_keys", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let result = match migrate_with_sql_locked(conn, migrations, true) {
        Ok(LockedMigrationOutcome::Complete) => Ok(()),
        Ok(LockedMigrationOutcome::RebuildRequired) => {
            Err("cache DB schema rebuild was not applied".to_string())
        }
        Err(err) => Err(err),
    };
    let restore = conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"));
    result.and(restore)
}

enum LockedMigrationOutcome {
    Complete,
    RebuildRequired,
}

enum BaselinePreparation {
    Ready(i64),
    RebuildRequired,
}

fn migrate_with_sql_locked(
    conn: &mut Connection,
    migrations: &[&str],
    rebuild_invalid_schema: bool,
) -> Result<LockedMigrationOutcome> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let user_version = cache_migration_version(&tx)?;
    if user_version < 0 {
        return Err(format!(
            "cache DB migration user_version must not be negative: {user_version}"
        ));
    }
    if user_version as usize > migrations.len() {
        // Version skew no longer reaches here: a build opens only the store
        // named for its own schema, and imports from an older one instead of
        // migrating it (issue #1589). A file whose name claims this schema and
        // whose user_version claims a later one is corrupt, so say what to do
        // with it rather than leaving the workspace unopenable.
        return Err(format!(
            "cache DB migration error: DatabaseTooFarAhead: user_version {user_version} exceeds {} in {}. \
             Each schema version has its own store file, so this file's contents contradict its name; \
             moving it aside is safe and this build will import the newest compatible older store or \
             start a fresh one.",
            migrations.len(),
            tx.path().unwrap_or("<in-memory>"),
        ));
    }
    if current_schema_fast_path(migrations, user_version) {
        tx.commit()
            .map_err(|err| format!("cache DB migration fast-path commit error: {err}"))?;
        return Ok(LockedMigrationOutcome::Complete);
    }

    let user_version = match prepare_baseline_migration(&tx, user_version, rebuild_invalid_schema)?
    {
        BaselinePreparation::Ready(user_version) => user_version,
        BaselinePreparation::RebuildRequired => {
            return Ok(LockedMigrationOutcome::RebuildRequired);
        }
    };
    let mut migration_applied = false;
    for (index, sql) in migrations.iter().enumerate().skip(user_version as usize) {
        let version = index + 1;
        tx.execute_batch(sql)
            .map_err(|err| format!("cache DB migration error applying version {version}: {err}"))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(|err| format!("cache DB migration error setting version {version}: {err}"))?;
        migration_applied = true;
    }
    if migration_applied {
        validate_foreign_keys(&tx)?;
    }
    tx.commit()
        .map_err(|err| format!("cache DB migration error: {err}"))?;
    Ok(LockedMigrationOutcome::Complete)
}

pub fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0)
}

fn delete_legacy_cache_files(db_path: &Path) {
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return;
    }
    let Some(parent) = db_path.parent() else {
        return;
    };
    for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
        delete_legacy_cache_if_idle(&parent.join(name));
    }
}

fn delete_legacy_cache_if_idle(legacy_path: &Path) {
    if !legacy_path.exists() {
        return;
    }
    let Ok(mut legacy) = Connection::open_with_flags(
        legacy_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ) else {
        return;
    };
    if legacy.busy_timeout(Duration::ZERO).is_err()
        || legacy
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .is_err()
    {
        return;
    }
    let checkpoint_busy = legacy
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(1);
    if checkpoint_busy != 0 {
        return;
    }
    let Ok(exclusive) = legacy.transaction_with_behavior(TransactionBehavior::Exclusive) else {
        return;
    };
    // Close first: Windows cannot unlink a database while the claiming handle is open.
    drop(exclusive);
    drop(legacy);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(store_file_with_suffix(legacy_path, suffix));
    }
}

fn recreate_schema(tx: &Transaction<'_>) -> Result<()> {
    for (object_type, name) in user_schema_objects(tx)? {
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        tx.execute_batch(&format!("DROP {object_type} {quoted};"))
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    }
    tx.pragma_update(None, "user_version", 0)
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

#[cfg(test)]
fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))
}

#[cfg(test)]
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
         )",
        [table, column],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn user_schema_objects(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND type IN ('view', 'trigger', 'table')
             ORDER BY CASE type
                 WHEN 'view' THEN 0
                 WHEN 'trigger' THEN 1
                 WHEN 'table' THEN 2
                 ELSE 3
             END, name",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<(String, String)>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn schema_object_definitions(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
             ORDER BY type, name",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| {
            let sql: String = row.get(2)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                sql.chars()
                    .filter(|character| !character.is_whitespace())
                    .collect(),
            ))
        })
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<(String, String, String)>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn prepare_baseline_migration(
    tx: &Transaction<'_>,
    user_version: i64,
    rebuild_invalid_schema: bool,
) -> Result<BaselinePreparation> {
    if user_version > BASELINE_MIGRATION_VERSION {
        return Ok(BaselinePreparation::Ready(user_version));
    }

    if user_version == 0 && user_schema_objects(tx)?.is_empty() {
        return Ok(BaselinePreparation::Ready(0));
    }

    if baseline_schema_is_valid(tx)? {
        if user_version == 0 {
            adopt_current_baseline(tx)?;
            return Ok(BaselinePreparation::Ready(BASELINE_MIGRATION_VERSION));
        }
        return Ok(BaselinePreparation::Ready(user_version));
    }

    if !rebuild_invalid_schema {
        return Ok(BaselinePreparation::RebuildRequired);
    }
    recreate_schema(tx)?;
    Ok(BaselinePreparation::Ready(0))
}

fn cache_migration_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn baseline_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    if schema_object_definitions(conn)? != *BASELINE_SCHEMA_OBJECTS {
        return Ok(false);
    }
    let versions = conn.query_row(
        "SELECT schema_version, semantic_schema_version, analyzer_schema_version
         FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    Ok(matches!(versions, Ok(versions) if versions == BASELINE_CACHE_STATE_VERSIONS))
}

#[cfg(test)]
fn current_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    if schema_object_definitions(conn)? != *CURRENT_SCHEMA_OBJECTS {
        return Ok(false);
    }
    let versions = conn.query_row(
        "SELECT schema_version, semantic_schema_version, analyzer_schema_version
         FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    Ok(matches!(versions, Ok(versions) if versions == BASELINE_CACHE_STATE_VERSIONS))
}

fn current_schema_fast_path(migrations: &[&str], user_version: i64) -> bool {
    migrations == CACHE_MIGRATION_SQL.as_slice() && user_version == CURRENT_MIGRATION_VERSION
}

fn quick_check_is_ok(conn: &Connection) -> Result<bool> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(result == "ok")
}

fn adopt_current_baseline(tx: &Transaction<'_>) -> Result<()> {
    if cache_migration_version(tx)? != 0 {
        return Ok(());
    }
    if !baseline_schema_is_valid(tx)? {
        return Err("cache DB baseline changed while being adopted".to_string());
    }
    tx.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn validate_foreign_keys(conn: &Connection) -> Result<()> {
    let violations: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    if violations == 0 {
        Ok(())
    } else {
        Err(format!(
            "cache DB migration foreign key validation failed with {violations} violation(s)"
        ))
    }
}

fn assert_sqlite_version(conn: &Connection) -> Result<()> {
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let parsed = parse_sqlite_version(&version)
        .ok_or_else(|| format!("unable to parse sqlite_version() output: {version}"))?;
    if parsed < SQLITE_MIN_VERSION {
        return Err(format!(
            "cache DB requires sqlite >= {}.{}.{} but found {version}",
            SQLITE_MIN_VERSION.0, SQLITE_MIN_VERSION.1, SQLITE_MIN_VERSION.2
        ));
    }
    Ok(())
}

fn parse_sqlite_version(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use rusqlite_migration::{M, Migrations};

    use super::*;

    fn open_in_memory_cache() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn
    }

    fn create_current_baseline_without_migration() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch(CURRENT_BASELINE_SQL).unwrap();
        conn
    }

    fn future_migration_sql(sql: &'static str) -> Vec<&'static str> {
        CACHE_MIGRATION_SQL
            .into_iter()
            .chain(std::iter::once(sql))
            .collect()
    }

    fn create_legacy_cache(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
    }

    /// A workspace whose `.bifrost` parent cannot be written must say how to
    /// proceed, in the order that keeps the shared cache intact (issue #1544).
    #[test]
    #[cfg(unix)]
    fn unwritable_workspace_root_reports_the_ways_out() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let workspace_root = temp.path().join("workspace");
        std::fs::create_dir(&workspace_root).unwrap();
        let db_path = workspace_root
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o555)).unwrap();

        let error = open_unified_connection(&db_path).unwrap_err();

        // Restored before any assertion can fail, so the tempdir still cleans up.
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            error.contains(&db_path.display().to_string())
                && error.contains(&workspace_root.display().to_string()),
            "the denied path must be named: {error}"
        );
        let elevate = error.find("elevated filesystem permissions").unwrap();
        let transient = error.find("deliberately transient").unwrap();
        let relocate = error.find("BIFROST_CACHE_DIR=<writable dir>").unwrap();
        assert!(
            elevate < transient && transient < relocate,
            "exits must stay ordered: {error}"
        );
        assert!(
            error.contains("neither benefits from nor contributes to the shared"),
            "relocation must carry its divergence warning: {error}"
        );
        assert!(
            !error.contains("unable to open database file"),
            "the raw SQLite error must be replaced: {error}"
        );
    }

    /// The same message when the cache directory itself exists but is
    /// read-only, which SQLite reports as a cause-free SQLITE_CANTOPEN.
    #[test]
    #[cfg(unix)]
    fn unwritable_cache_directory_reports_the_ways_out() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp
            .path()
            .join("workspace")
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME);
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join(".gitignore"), GENERATED_CACHE_GITIGNORE).unwrap();
        let db_path = cache_dir.join(cache_db_file_name());
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let error = open_unified_connection(&db_path).unwrap_err();

        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            error.contains(&cache_dir.display().to_string())
                && error.contains("elevated filesystem permissions"),
            "{error}"
        );
    }

    #[test]
    fn baseline_migration_validates() {
        CACHE_MIGRATIONS.validate().unwrap();
    }

    #[test]
    fn fresh_cache_applies_baseline_migration() {
        let conn = open_in_memory_cache();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn shared_cache_writer_wait_budget_covers_large_repo_reconcile() {
        let temp = tempfile::tempdir().unwrap();
        let conn = open_unified_connection(&temp.path().join(cache_db_file_name())).unwrap();
        let busy_timeout_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();

        assert!(
            busy_timeout_ms >= 60_000,
            "shared-cache writers need a substantial serialization budget, got {busy_timeout_ms}ms"
        );
    }

    #[test]
    fn streaming_reader_has_a_small_non_mmap_page_cache() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let _writer = open_unified_connection(&db_path).unwrap();
        let conn = open_streaming_readonly_connection(&db_path).unwrap();

        assert_eq!(
            conn.query_row("PRAGMA cache_size", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            -2048
        );
        assert_eq!(
            conn.query_row("PRAGMA mmap_size", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn active_session_can_write_temp_but_not_main() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let _writer = open_unified_connection(&db_path).unwrap();
        let conn = open_readonly_temp_connection(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TEMP TABLE active_test(value TEXT PRIMARY KEY) WITHOUT ROWID, STRICT;
             INSERT INTO active_test VALUES('ok');",
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT value FROM active_test", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "ok"
        );
        assert!(
            conn.execute("UPDATE cache_state SET last_gc_at = 1 WHERE id = 1", [])
                .is_err()
        );
    }

    #[test]
    fn concurrent_fresh_cache_openers_serialize_schema_migration() {
        const OPENERS: usize = 16;

        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let barrier = Arc::new(Barrier::new(OPENERS));
        let results = thread::scope(|scope| {
            let handles = (0..OPENERS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let db_path = db_path.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        let conn = open_unified_connection(&db_path)?;
                        if cache_migration_version(&conn)? != CURRENT_MIGRATION_VERSION {
                            return Err("concurrent opener observed an old schema version".into());
                        }
                        if !current_schema_is_valid(&conn)? {
                            return Err("concurrent opener observed an invalid schema".into());
                        }
                        let foreign_keys: i64 = conn
                            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if foreign_keys != 1 {
                            return Err("concurrent opener left foreign keys disabled".into());
                        }
                        let journal_mode: String = conn
                            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if !journal_mode.eq_ignore_ascii_case("wal") {
                            return Err(format!(
                                "concurrent opener observed journal_mode={journal_mode}"
                            ));
                        }
                        let auto_vacuum: i64 = conn
                            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if auto_vacuum != 2 {
                            return Err(format!(
                                "concurrent opener observed auto_vacuum={auto_vacuum}"
                            ));
                        }
                        Ok(())
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("cache opener thread panicked"))
                .collect::<Vec<_>>()
        });

        assert!(
            results.iter().all(Result::is_ok),
            "concurrent cache openers failed: {results:#?}"
        );
        let conn = open_unified_connection(&db_path).unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        assert!(quick_check_is_ok(&conn).unwrap());
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn process_local_open_lock_reuses_same_canonical_path_cell() {
        let temp = tempfile::tempdir().unwrap();
        let canonical = prepare_cache_db_path(&temp.path().join(cache_db_file_name())).unwrap();
        let alternate = prepare_cache_db_path(
            &temp
                .path()
                .join(".")
                .join("nested")
                .join("..")
                .join(cache_db_file_name()),
        )
        .unwrap();

        let first = process_local_open_lock_cell(&canonical).unwrap();
        let second = process_local_open_lock_cell(&alternate).unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "same canonical cache path must reuse one in-process lock cell"
        );
    }

    #[test]
    fn process_local_open_lock_distinguishes_independent_paths() {
        let temp = tempfile::tempdir().unwrap();
        let left = prepare_cache_db_path(&temp.path().join("left.db")).unwrap();
        let right = prepare_cache_db_path(&temp.path().join("right.db")).unwrap();

        let left_lock = process_local_open_lock_cell(&left).unwrap();
        let right_lock = process_local_open_lock_cell(&right).unwrap();

        assert!(
            !Arc::ptr_eq(&left_lock, &right_lock),
            "independent cache paths must not share one global lock cell"
        );
    }

    #[test]
    fn populated_mode_zero_cache_keeps_compatible_auto_vacuum_policy() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let mut conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE existing(value TEXT) STRICT;")
            .unwrap();
        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );

        configure_connection(&mut conn).unwrap();

        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0,
            "populated mode-0 databases require an explicit VACUUM and must not be reported as converted"
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
    }

    fn sqlite_initialization_error(code: i32) -> InitializationPhaseError {
        InitializationPhaseError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            None,
        ))
    }

    #[test]
    fn initialization_retry_retries_busy_but_not_locked() {
        let mut busy_attempts = 0;
        let value = retry_initialization_phase_with(
            "test busy phase",
            Duration::from_secs(1),
            |_| {},
            || {
                busy_attempts += 1;
                if busy_attempts < 3 {
                    Err(sqlite_initialization_error(rusqlite::ffi::SQLITE_BUSY))
                } else {
                    Ok(42)
                }
            },
        )
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(busy_attempts, 3);

        let mut locked_attempts = 0;
        let error = retry_initialization_phase_with(
            "test locked phase",
            Duration::from_secs(1),
            |_| {},
            || {
                locked_attempts += 1;
                Err::<(), _>(sqlite_initialization_error(rusqlite::ffi::SQLITE_LOCKED))
            },
        )
        .unwrap_err();
        assert_eq!(locked_attempts, 1);
        assert!(error.contains("test locked phase SQLite error"), "{error}");
        assert!(!error.contains("timed out"), "{error}");
    }

    #[test]
    fn initialization_retry_reports_busy_deadline_without_sleeping() {
        let mut attempts = 0;
        let error = retry_initialization_phase_with(
            "test timeout phase",
            Duration::ZERO,
            |_| panic!("zero-deadline retry must not sleep"),
            || {
                attempts += 1;
                Err::<(), _>(sqlite_initialization_error(rusqlite::ffi::SQLITE_BUSY))
            },
        )
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(error.contains("test timeout phase timed out"), "{error}");
    }

    #[test]
    fn current_pre_migration_cache_rebuilds_semantic_rows_and_invalidates_analyzer_rows() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, 'rust')",
            ["1111111111111111111111111111111111111111"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let semantic_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM semantic_files", [], |row| row.get(0))
            .unwrap();
        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(semantic_count, 0);
        assert_eq!(analyzer_count, 0);
    }

    #[test]
    fn analyzer_migrations_preserve_populated_v3_rows_with_lazy_payload_costs() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        Migrations::new(vec![
            M::up(CURRENT_BASELINE_SQL),
            M::up(PATH_SYMBOL_UNITS_SQL),
            M::up(FORWARD_FACTS_SQL),
        ])
        .to_latest(&mut conn)
        .unwrap();
        let semantic_oid = "1111111111111111111111111111111111111111";
        let analyzer_oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, 'rust')",
            [semantic_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO type_identifiers(blob_oid, lang, type_identifier)
             VALUES(?1, 'rust', 'PersistedType')",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_oid, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, import_count, type_identifier_count,
               ruby_dispatch_count, scala_trait_count, is_complete
             ) VALUES(?1, 'rust', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1)",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO path_symbol_units(
               lang, rel_path, blob_oid, kind, package_name, short_name,
               exact_fqn, normalized_fqn
             ) VALUES('rust', 'src/lib.rs', ?1, 0, 'src', 'lib', 'src.lib', 'src.lib')",
            [analyzer_oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row("SELECT generation FROM blobs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_payload_costs", [], |row| row
                .get::<_, i64>(0),)
                .unwrap(),
            0,
            "the migration must preserve populated analyzer rows for lazy fallback"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('blobs')
                 WHERE name IN ('cascade_logical_rows', 'cascade_payload_bytes')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2,
            "the published v5 columns must remain present after additive v6 migration"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_meta", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM type_identifiers", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT generation FROM path_symbol_units", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM semantic_files", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn populated_v5_cache_migrates_additively_to_v7() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        Migrations::new(vec![
            M::up(CURRENT_BASELINE_SQL),
            M::up(PATH_SYMBOL_UNITS_SQL),
            M::up(FORWARD_FACTS_SQL),
            M::up(ANALYZER_GENERATIONS_SQL),
            M::up(ANALYZER_BLOB_CASCADE_COSTS_SQL),
        ])
        .to_latest(&mut conn)
        .unwrap();
        let analyzer_oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO blobs(
               blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes
             ) VALUES(?1, 'rust', 7, 3, 11)",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_oid, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, import_count, type_identifier_count,
               ruby_dispatch_count, scala_trait_count, is_complete
             ) VALUES(?1, 'rust', 0, 'unicode_é', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)",
            [analyzer_oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row(
                "SELECT generation, cascade_logical_rows, cascade_payload_bytes FROM blobs",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )
            .unwrap(),
            (7, 3, 11),
            "later additive migrations must not reinterpret already-applied v5 state"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_payload_costs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0,
            "existing parsed blobs intentionally retain the v6 legacy-fallback state"
        );
        assert_eq!(
            conn.query_row("SELECT content_package FROM blob_meta", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "unicode_é"
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn populated_v10_cache_migrates_additively_to_code_unit_test_region() {
        // A code_units row written before migration 0011 must survive the
        // additive `in_test_region` column, which defaults to 0 (untainted).
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        Migrations::new(vec![
            M::up(CURRENT_BASELINE_SQL),
            M::up(PATH_SYMBOL_UNITS_SQL),
            M::up(FORWARD_FACTS_SQL),
            M::up(ANALYZER_GENERATIONS_SQL),
            M::up(ANALYZER_BLOB_CASCADE_COSTS_SQL),
            M::up(ANALYZER_BLOB_PAYLOAD_COSTS_SQL),
            M::up(STRUCTURAL_FACTS_SNAPSHOTS_SQL),
            M::up(CPP_TEMPLATE_METADATA_SQL),
            M::up(SCALA_EXPORTS_SQL),
            M::up(IDENTIFIER_LOOKUP_MEMBERSHIP_SQL),
        ])
        .to_latest(&mut conn)
        .unwrap();
        let oid = "3333333333333333333333333333333333333333";
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 11)",
            [oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               synthetic, is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', 0, 1, 'make_widget', 'make_widget', '', 0, 0, 0, 1, 0)",
            [oid],
        )
        .unwrap();

        // The column does not exist before migration 0011.
        let before: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM pragma_table_info('code_units')
                   WHERE name = 'in_test_region'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!before, "in_test_region should not exist before 0011");

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row(
                "SELECT short_name, in_test_region FROM code_units",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
            ("make_widget".to_string(), 0),
            "pre-existing units default to untainted after the additive column"
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn incomplete_pre_migration_cache_is_rebuilt() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_table_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_incomplete_table_shape_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch(
            "DROP TABLE blob_meta;
             CREATE TABLE blob_meta(
               blob_oid TEXT NOT NULL,
               lang TEXT NOT NULL,
               PRIMARY KEY(blob_oid, lang)
             ) WITHOUT ROWID, STRICT;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let has_content_package: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM pragma_table_info('blob_meta')
                   WHERE name = 'content_package'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(has_content_package);
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_view_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE VIEW legacy_view AS SELECT 1 AS value;")
            .unwrap();

        migrate(&mut conn).unwrap();

        let legacy_view_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = 'legacy_view'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!legacy_view_exists);
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn incomplete_current_cache_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch(
            "DROP TABLE semantic_vectors;
             PRAGMA user_version = 1;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn fq_segments_migration_upgrades_pre_column_database() {
        // Build a database at the schema version that predates the fq_segments
        // column (everything through 0011), insert a code_units row the old way
        // (no fq_segments), then run the full migration and prove the ALTER
        // lands cleanly and the pre-existing row survives with a NULL segments
        // blob (which the load path decodes to an empty FqName; the epoch salt
        // bump forces such rows to re-extract and repopulate real segments).
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        let pre_column = &CACHE_MIGRATION_SQL[..11];
        migrate_with_sql(&mut conn, pre_column).unwrap();
        assert_eq!(cache_migration_version(&conn).unwrap(), 11);
        assert!(!column_exists(&conn, "code_units", "fq_segments").unwrap());

        let oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier, content_qualifier,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', 1, 2, 'Widget', 'Widget', '', NULL, 0, 0, 0, 1, 0)",
            [oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(column_exists(&conn, "code_units", "fq_segments").unwrap());
        assert!(current_schema_is_valid(&conn).unwrap());
        let (short_name, fq_segments): (String, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT short_name, fq_segments FROM code_units WHERE blob_oid = ?1",
                [oid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(short_name, "Widget");
        assert_eq!(fq_segments, None);
    }

    #[test]
    fn semantic_pack_active_set_migration_preserves_analyzer_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        let before_active_sets = &CACHE_MIGRATION_SQL[..12];
        migrate_with_sql(&mut conn, before_active_sets).unwrap();
        assert_eq!(cache_migration_version(&conn).unwrap(), 12);
        let oid = "3333333333333333333333333333333333333333";
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(table_exists(&conn, "semantic_pack_active_state").unwrap());
        assert!(table_exists(&conn, "semantic_pack_active_members").unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1",
                [oid],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn semantic_file_document_migration_rebuilds_only_semantic_index_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        let before_file_documents = &CACHE_MIGRATION_SQL[..13];
        migrate_with_sql(&mut conn, before_file_documents).unwrap();
        let semantic_oid = "1111111111111111111111111111111111111111";
        let analyzer_oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, 'rust')",
            [semantic_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO semantic_pack_active_state(singleton, active_set_digest, updated_at)
             VALUES(1, ?1, 1)",
            ["a".repeat(64)],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM semantic_files", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM semantic_pack_active_state",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            1
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn optional_fact_manifest_migration_preserves_populated_v15_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        let version_15 = &CACHE_MIGRATION_SQL[..15];
        migrate_with_sql(&mut conn, version_15).unwrap();
        assert_eq!(cache_migration_version(&conn).unwrap(), 15);

        conn.execute_batch(
            "INSERT INTO blobs(blob_oid, lang) VALUES
               ('1111111111111111111111111111111111111111', 'cpp'),
               ('2222222222222222222222222222222222222222', 'ruby'),
               ('3333333333333333333333333333333333333333', 'scala'),
               ('4444444444444444444444444444444444444444', 'rust');

             INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES
               ('1111111111111111111111111111111111111111', 'cpp', 1, 0,
                'TemplateOne', 'TemplateOne', '', 0, 0, 0, 1, 0),
               ('1111111111111111111111111111111111111111', 'cpp', 2, 0,
                'TemplateTwo', 'TemplateTwo', '', 0, 0, 1, 1, 0),
               ('2222222222222222222222222222222222222222', 'ruby', 1, 2,
                'dispatch', 'dispatch', '', 0, 0, 0, 1, 0),
               ('3333333333333333333333333333333333333333', 'scala', 1, 0,
                'ExportOwner', 'ExportOwner', '', 0, 0, 0, 1, 0);

             INSERT INTO blob_meta(
               blob_oid, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, import_count, type_identifier_count,
               ruby_dispatch_count, scala_trait_count, is_complete,
               cpp_template_metadata_count
             ) VALUES
               ('1111111111111111111111111111111111111111', 'cpp', 0, 'cpp.pkg',
                2, 11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 1, 3),
               ('2222222222222222222222222222222222222222', 'ruby', 0, 'ruby.pkg',
                1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0),
               ('3333333333333333333333333333333333333333', 'scala', 0, 'scala.pkg',
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0),
               ('4444444444444444444444444444444444444444', 'rust', 0, 'rust.pkg',
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0);

             INSERT INTO unit_cpp_template_metadata(blob_oid, lang, unit_key, metadata) VALUES
               ('1111111111111111111111111111111111111111', 'cpp', 1, X'01'),
               ('1111111111111111111111111111111111111111', 'cpp', 2, X'02');
             INSERT INTO ruby_method_dispatch_modes(blob_oid, lang, unit_key, mode) VALUES
               ('2222222222222222222222222222222222222222', 'ruby', 1, 2);
             INSERT INTO scala_traits(blob_oid, lang, unit_key) VALUES
               ('3333333333333333333333333333333333333333', 'scala', 1);
             INSERT INTO scala_exports(blob_oid, lang, owner_key, ordinal, info) VALUES
               ('3333333333333333333333333333333333333333', 'scala', 1, 0, X'03'),
               ('3333333333333333333333333333333333333333', 'scala', 1, 1, X'04');
             INSERT INTO materialization_records(blob_oid, lang, ordinal, unit_key, payload) VALUES
               ('4444444444444444444444444444444444444444', 'rust', 0, NULL, X'05'),
               ('4444444444444444444444444444444444444444', 'rust', 1, NULL, X'06');

             INSERT INTO blob_payload_costs(blob_oid, lang, payload_bytes) VALUES
               ('1111111111111111111111111111111111111111', 'cpp', 73);
             INSERT INTO structural_facts_snapshots(
               blob_oid, lang, snapshot_version, payload
             ) VALUES
               ('1111111111111111111111111111111111111111', 'cpp', 4, X'0708');",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        let manifest_rows = conn
            .prepare(
                "SELECT fact_kind, lang, row_count
                 FROM blob_optional_fact_manifest
                 ORDER BY fact_kind",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            manifest_rows,
            vec![
                (
                    OPTIONAL_FACT_KIND_CPP_TEMPLATE_METADATA,
                    "cpp".to_string(),
                    3
                ),
                (
                    OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE,
                    "ruby".to_string(),
                    1,
                ),
                (OPTIONAL_FACT_KIND_SCALA_TRAIT, "scala".to_string(), 1),
                (OPTIONAL_FACT_KIND_SCALA_EXPORT, "scala".to_string(), 2),
                (
                    OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD,
                    "rust".to_string(),
                    2,
                ),
            ]
        );
        assert!(
            conn.execute(
                "INSERT INTO blob_optional_fact_manifest(
                   blob_oid, lang, fact_kind, row_count
                 ) VALUES(
                   '1111111111111111111111111111111111111111', 'cpp', 5, 0
                 )",
                [],
            )
            .is_err(),
            "the sparse manifest must not store zero counts"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('blob_meta')
                 WHERE name IN (
                   'cpp_template_metadata_count',
                   'ruby_dispatch_count',
                   'scala_trait_count'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_meta", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            4
        );
        assert_eq!(
            conn.query_row(
                "SELECT GROUP_CONCAT(content_package, ',')
                 FROM (SELECT content_package FROM blob_meta ORDER BY lang)",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "cpp.pkg,ruby.pkg,rust.pkg,scala.pkg"
        );
        assert_eq!(
            conn.query_row(
                "SELECT stored_unit_count, range_count, signature_count,
                        signature_metadata_count, supertype_count, child_count,
                        import_statement_count, import_count, type_identifier_count
                 FROM blob_meta
                 WHERE blob_oid = '1111111111111111111111111111111111111111'
                   AND lang = 'cpp'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .unwrap(),
            (2, 11, 12, 13, 14, 15, 16, 17, 18)
        );
        assert_eq!(
            conn.query_row("SELECT payload_bytes FROM blob_payload_costs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            73
        );
        assert_eq!(
            conn.query_row(
                "SELECT snapshot_version, hex(payload) FROM structural_facts_snapshots",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
            (4, "0708".to_string())
        );
        assert_eq!(
            conn.query_row(
                "SELECT
                   (SELECT COUNT(*) FROM unit_cpp_template_metadata) +
                   (SELECT COUNT(*) FROM ruby_method_dispatch_modes) +
                   (SELECT COUNT(*) FROM scala_traits) +
                   (SELECT COUNT(*) FROM scala_exports) +
                   (SELECT COUNT(*) FROM materialization_records)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            8
        );
        conn.execute(
            "INSERT INTO blob_optional_fact_manifest(
               blob_oid, lang, fact_kind, row_count
             ) VALUES(
               '4444444444444444444444444444444444444444', 'rust', 99, 1
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM blob_meta
             WHERE blob_oid = '4444444444444444444444444444444444444444'
               AND lang = 'rust'",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blob_optional_fact_manifest WHERE lang = 'rust'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "manifest rows must follow their parsed metadata lifetime"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn future_migration_preserves_baseline_rows() {
        let mut conn = open_in_memory_cache();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();
        let migrations =
            future_migration_sql("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        migrate_with_sql(&mut conn, &migrations).unwrap();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert_eq!(analyzer_count, 1);
        assert!(table_exists(&conn, "migration_probe").unwrap());
    }

    #[test]
    fn failing_migration_rolls_back_schema_and_version() {
        let mut conn = open_in_memory_cache();
        let migrations = future_migration_sql(
            "CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;
             this is not valid SQL;",
        );

        assert!(migrate_with_sql(&mut conn, &migrations).is_err());

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "migration_probe").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn foreign_key_validation_rolls_back_schema_and_version() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
        let migrations = future_migration_sql(
            "INSERT INTO blob_payload_costs(blob_oid, lang, payload_bytes)
             VALUES('0000000000000000000000000000000000000000', 'rust', 0);",
        );

        let err = migrate_with_sql(&mut conn, &migrations).unwrap_err();

        assert!(
            err.contains("foreign key validation failed"),
            "unexpected error: {err}"
        );
        assert_eq!(cache_migration_version(&conn).unwrap(), 0);
        assert!(table_exists(&conn, "legacy_cache").unwrap());
        assert!(!table_exists(&conn, "blob_payload_costs").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn locked_migration_retries_after_writer_releases_lock() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let mut conn = Connection::open(&db_path).unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn.busy_timeout(Duration::ZERO).unwrap();

        let mut blocker = Connection::open(&db_path).unwrap();
        blocker.busy_timeout(Duration::ZERO).unwrap();
        let writer = blocker
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        migrate(&mut conn).expect("a valid current schema must not wait for the write lock");
        let migrations =
            future_migration_sql("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        assert!(migrate_with_sql(&mut conn, &migrations).is_err());
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "migration_probe").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );

        writer.rollback().unwrap();
        migrate_with_sql(&mut conn, &migrations).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert!(table_exists(&conn, "migration_probe").unwrap());
    }

    #[test]
    fn newer_migration_version_is_refused_without_mutating_cache() {
        let mut conn = open_in_memory_cache();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", CURRENT_MIGRATION_VERSION + 1)
            .unwrap();

        let err = migrate(&mut conn).unwrap_err();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert!(
            err.contains("DatabaseTooFarAhead"),
            "unexpected error: {err}"
        );
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert_eq!(analyzer_count, 1);
    }

    #[test]
    fn first_unified_open_removes_only_idle_legacy_caches_after_migration() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
            create_legacy_cache(&cache_dir.join(name));
        }

        let unified = cache_dir.join(cache_db_file_name());
        let connection = open_unified_connection(&unified).unwrap();

        assert!(unified_cache_initialized(&connection).unwrap());
        for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
            assert!(!cache_dir.join(name).exists());
        }
    }

    #[test]
    fn baseline_adoption_does_not_remove_legacy_caches() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_cache(&legacy);

        let unified = cache_dir.join(cache_db_file_name());
        let mut pre_migration = Connection::open(&unified).unwrap();
        configure_connection(&mut pre_migration).unwrap();
        pre_migration.execute_batch(CURRENT_BASELINE_SQL).unwrap();
        drop(pre_migration);

        let connection = open_unified_connection(&unified).unwrap();

        assert_eq!(
            cache_migration_version(&connection).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(legacy.exists());
    }

    #[test]
    fn custom_database_open_does_not_remove_legacy_caches() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_cache(&legacy);

        let _custom = open_unified_connection(&cache_dir.join("custom.db")).unwrap();

        assert!(legacy.exists());
    }

    #[test]
    fn active_legacy_writer_survives_first_unified_open() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy_path = cache_dir.join(LEGACY_ANALYZER_DB_FILE_NAME);
        let mut legacy = Connection::open(&legacy_path).unwrap();
        legacy.pragma_update(None, "journal_mode", "WAL").unwrap();
        legacy
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
        let writer = legacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        writer
            .execute("INSERT INTO legacy_cache(value) VALUES('active')", [])
            .unwrap();

        let _unified = open_unified_connection(&cache_dir.join(cache_db_file_name())).unwrap();

        assert!(legacy_path.exists());
        writer.rollback().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let cache_dir = temp.path().join(".bifrost");
        symlink(&outside, &cache_dir).unwrap();

        let err = open_unified_connection(&cache_dir.join(cache_db_file_name())).unwrap_err();
        assert!(
            err.contains("cache directory symlink"),
            "unexpected error: {err}"
        );
        assert!(!outside.join(cache_db_file_name()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_database() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        let outside = temp.path().join("outside.db");
        symlink(&outside, cache_dir.join(cache_db_file_name())).unwrap();

        let err = open_unified_connection(&cache_dir.join(cache_db_file_name())).unwrap_err();
        assert!(
            err.contains("cache database symlink"),
            "unexpected error: {err}"
        );
        assert!(!outside.exists());
    }

    /// Opening the cache inside a git working tree must leave the cache
    /// directory *ignored* while project-owned `.bifrost` configuration remains
    /// visible to Git. This is the property that keeps `analyze_diff` from
    /// trying to read `bifrost_cache.db-wal` as untracked content while SQLite
    /// is writing it (`file changed before we could read it; class=Filesystem
    /// (30)`) without hiding policies or reviewed suppressions from version
    /// control.
    #[test]
    fn cache_is_ignored_while_project_configuration_remains_trackable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        std::fs::write(root.join("lib.go"), "package sample\n").unwrap();

        let project_dir = root.join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir_all(project_dir.join("policies")).unwrap();
        std::fs::write(
            project_dir.join("policies/example.rqlp"),
            "(policy :schema-version 1)\n",
        )
        .unwrap();
        std::fs::write(
            project_dir.join("suppressions.json"),
            "{\"schema_version\":1}\n",
        )
        .unwrap();

        let cache_dir = project_dir.join(crate::gitblob::CACHE_SUBDIR_NAME);
        let _conn = open_unified_connection(&cache_dir.join(cache_db_file_name())).unwrap();

        // Workdir-relative: on macOS the temp root is a `/var` symlink to
        // `/private/var`, so an absolute path would not be recognized as living
        // inside the repository.
        let relative_cache_dir =
            Path::new(crate::gitblob::PROJECT_DIR_NAME).join(crate::gitblob::CACHE_SUBDIR_NAME);
        let relative_db = relative_cache_dir.join(cache_db_file_name());
        assert!(
            repo.is_path_ignored(&relative_db).unwrap(),
            "the cache database must be ignored by git"
        );
        assert!(
            repo.is_path_ignored(
                Path::new(crate::gitblob::PROJECT_DIR_NAME)
                    .join(crate::gitblob::CACHE_SUBDIR_NAME)
                    .join(format!("{}-wal", cache_db_file_name()))
            )
            .unwrap(),
            "the write-ahead log -- the file `analyze_diff` raced with -- must be ignored"
        );
        // The untracked walk `analyze_diff` performs must surface real sources
        // and nothing from the cache directory.
        let mut options = git2::StatusOptions::new();
        options.include_untracked(true).recurse_untracked_dirs(true);
        let untracked: Vec<String> = repo
            .statuses(Some(&mut options))
            .unwrap()
            .iter()
            .filter_map(|entry| entry.path().map(str::to_string))
            .collect();
        assert!(
            untracked.iter().any(|path| path == "lib.go"),
            "real sources must still be visible: {untracked:?}"
        );
        for tracked_input in [
            ".bifrost/policies/example.rqlp",
            ".bifrost/suppressions.json",
        ] {
            assert!(
                untracked.iter().any(|path| path == tracked_input),
                "project-owned Bifrost input must remain visible to Git: {untracked:?}"
            );
        }
        assert!(
            !untracked
                .iter()
                .any(|path| path.starts_with(relative_cache_dir.to_string_lossy().as_ref())),
            "cache directory leaked into the untracked walk: {untracked:?}"
        );
    }

    #[test]
    fn default_cache_open_narrows_exact_generated_legacy_layout_without_deleting_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let project_dir = root.join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir_all(project_dir.join("policies")).unwrap();
        std::fs::write(project_dir.join(".gitignore"), GENERATED_CACHE_GITIGNORE).unwrap();
        std::fs::write(
            project_dir.join("policies/example.rqlp"),
            "(policy :schema-version 1)\n",
        )
        .unwrap();
        let legacy_db = project_dir.join(LEGACY_CACHE_DB_FILE_NAME);
        let legacy = Connection::open(&legacy_db).unwrap();
        legacy
            .execute_batch("CREATE TABLE legacy(value TEXT) STRICT;")
            .unwrap();
        drop(legacy);

        let cache_dir = project_dir.join(crate::gitblob::CACHE_SUBDIR_NAME);
        let db_path = cache_dir.join(cache_db_file_name());
        let _connection = open_unified_connection(&db_path).unwrap();

        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert!(legacy_db.exists());
        assert_eq!(
            std::fs::read(cache_dir.join(".gitignore")).unwrap(),
            GENERATED_CACHE_GITIGNORE
        );
        assert!(
            !repo
                .is_path_ignored(Path::new(".bifrost/policies/example.rqlp"))
                .unwrap()
        );
        assert!(
            repo.is_path_ignored(Path::new(".bifrost/bifrost_cache.db"))
                .unwrap()
        );
        assert!(
            repo.is_path_ignored(
                Path::new(crate::gitblob::PROJECT_DIR_NAME)
                    .join(crate::gitblob::CACHE_SUBDIR_NAME)
                    .join(cache_db_file_name())
            )
            .unwrap()
        );
    }

    #[test]
    fn default_cache_open_protects_legacy_state_when_project_ignore_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let project_dir = root.join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        let legacy_db = project_dir.join(LEGACY_CACHE_DB_FILE_NAME);
        create_legacy_cache(&legacy_db);
        let db_path = project_dir
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());

        let _connection = open_unified_connection(&db_path).unwrap();

        assert!(legacy_db.exists());
        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert!(
            repo.is_path_ignored(Path::new(".bifrost/.gitignore"))
                .unwrap()
        );
        assert!(
            repo.is_path_ignored(Path::new(".bifrost/bifrost_cache.db"))
                .unwrap()
        );
    }

    #[test]
    fn active_legacy_writer_survives_default_layout_migration() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        std::fs::write(project_dir.join(".gitignore"), GENERATED_CACHE_GITIGNORE).unwrap();
        let legacy_db = project_dir.join(LEGACY_CACHE_DB_FILE_NAME);
        let mut legacy = Connection::open(&legacy_db).unwrap();
        legacy.pragma_update(None, "journal_mode", "WAL").unwrap();
        legacy
            .execute_batch("CREATE TABLE legacy(value TEXT) STRICT;")
            .unwrap();
        let writer = legacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        writer
            .execute("INSERT INTO legacy(value) VALUES('active')", [])
            .unwrap();
        let db_path = project_dir
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());

        let _connection = open_unified_connection(&db_path).unwrap();
        writer.commit().unwrap();

        assert!(legacy_db.exists());
        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert_eq!(
            legacy
                .query_row("SELECT value FROM legacy", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "active"
        );
    }

    #[test]
    fn concurrent_default_layout_upgrades_publish_one_complete_narrow_ignore() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        std::fs::write(project_dir.join(".gitignore"), GENERATED_CACHE_GITIGNORE).unwrap();
        create_legacy_cache(&project_dir.join(LEGACY_CACHE_DB_FILE_NAME));
        let db_path = Arc::new(
            project_dir
                .join(crate::gitblob::CACHE_SUBDIR_NAME)
                .join(cache_db_file_name()),
        );
        let barrier = Arc::new(std::sync::Barrier::new(5));

        let handles = (0..4)
            .map(|_| {
                let db_path = Arc::clone(&db_path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    open_unified_connection(db_path.as_ref())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            handle
                .join()
                .expect("upgrade thread")
                .expect("concurrent upgrade");
        }

        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert!(project_dir.join(LEGACY_CACHE_DB_FILE_NAME).exists());
    }

    #[test]
    fn concurrent_upgrades_publish_a_complete_ignore_when_it_was_missing() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        create_legacy_cache(&project_dir.join(LEGACY_CACHE_DB_FILE_NAME));
        let db_path = Arc::new(
            project_dir
                .join(crate::gitblob::CACHE_SUBDIR_NAME)
                .join(cache_db_file_name()),
        );
        let barrier = Arc::new(std::sync::Barrier::new(5));

        let handles = (0..4)
            .map(|_| {
                let db_path = Arc::clone(&db_path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    open_unified_connection(db_path.as_ref())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            handle
                .join()
                .expect("upgrade thread")
                .expect("concurrent missing-ignore upgrade");
        }

        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert!(project_dir.join(LEGACY_CACHE_DB_FILE_NAME).exists());
    }

    #[test]
    fn explicit_cache_override_is_not_treated_as_project_layout() {
        let db_path = Path::new("workspace")
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());
        let db_path = db_path.as_path();

        assert!(default_project_dir_for_cache_with_override(db_path, None).is_some());
        assert!(
            default_project_dir_for_cache_with_override(db_path, Some(db_path)).is_none(),
            "BIFROST_CACHE_DIR keeps its explicit-directory semantics even when it names the conventional path"
        );
    }

    #[test]
    fn default_cache_open_keeps_orphaned_legacy_sidecars_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        std::fs::write(project_dir.join(".gitignore"), GENERATED_CACHE_GITIGNORE).unwrap();
        let orphaned_journal = project_dir.join("bifrost_cache.db-journal");
        std::fs::write(&orphaned_journal, "legacy").unwrap();
        let db_path = project_dir
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());

        let _connection = open_unified_connection(&db_path).unwrap();

        assert!(orphaned_journal.exists());
        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
    }

    #[test]
    fn user_modified_legacy_whole_directory_ignore_is_preserved_and_reported() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        let ignore_path = project_dir.join(".gitignore");
        let custom_ignore = b"*\n# retained by the user\n";
        std::fs::write(&ignore_path, custom_ignore).unwrap();
        let legacy_db = project_dir.join(LEGACY_CACHE_DB_FILE_NAME);
        std::fs::write(&legacy_db, "legacy cache bytes").unwrap();
        let db_path = project_dir
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());

        let error = open_unified_connection(&db_path).unwrap_err();

        assert!(error.contains("still ignores all tracked .bifrost configuration"));
        assert_eq!(std::fs::read(&ignore_path).unwrap(), custom_ignore);
        assert_eq!(std::fs::read(&legacy_db).unwrap(), b"legacy cache bytes");
        assert!(!project_dir.join(crate::gitblob::CACHE_SUBDIR_NAME).exists());
    }

    #[test]
    fn user_authored_narrow_project_ignore_is_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        let ignore_path = project_dir.join(".gitignore");
        let custom_ignore = b"local-notes.txt\n";
        std::fs::write(&ignore_path, custom_ignore).unwrap();
        let db_path = project_dir
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(cache_db_file_name());

        let _connection = open_unified_connection(&db_path).unwrap();

        assert_eq!(std::fs::read(&ignore_path).unwrap(), custom_ignore);
    }

    /// The self-ignore is written once and then left alone: reopening must not
    /// rewrite it (which would churn its mtime inside a watched tree), and a
    /// user's own edit to it must survive.
    #[test]
    fn cache_directory_self_ignore_is_written_once_and_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp
            .path()
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME);
        let db_path = cache_dir.join(cache_db_file_name());

        let _conn = open_unified_connection(&db_path).unwrap();
        let ignore_path = cache_dir.join(".gitignore");
        assert_eq!(std::fs::read_to_string(&ignore_path).unwrap(), "*\n");

        std::fs::write(&ignore_path, "*\n# edited by the user\n").unwrap();
        drop(_conn);
        let _reopened = open_unified_connection(&db_path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&ignore_path).unwrap(),
            "*\n# edited by the user\n",
            "reopening must not rewrite an existing self-ignore"
        );
    }

    #[test]
    fn cache_directory_ignore_cannot_expose_generated_database_files() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp
            .path()
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME);
        std::fs::create_dir_all(&cache_dir).unwrap();
        let ignore_path = cache_dir.join(".gitignore");
        let unsafe_ignore = format!("*\n!{}\n", cache_db_file_name());
        std::fs::write(&ignore_path, &unsafe_ignore).unwrap();
        let db_path = cache_dir.join(cache_db_file_name());

        let error = open_unified_connection(&db_path).unwrap_err();

        assert!(error.contains("does not ignore generated state"));
        assert_eq!(
            std::fs::read(ignore_path).unwrap(),
            unsafe_ignore.as_bytes()
        );
        assert!(!db_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cache_directory_ignore_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp
            .path()
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME);
        std::fs::create_dir_all(&cache_dir).unwrap();
        let outside = temp.path().join("outside-ignore");
        std::fs::write(&outside, "outside\n").unwrap();
        symlink(&outside, cache_dir.join(".gitignore")).unwrap();
        let db_path = cache_dir.join(cache_db_file_name());

        let error = open_unified_connection(&db_path).unwrap_err();

        assert!(error.contains("cache directory ignore is not a regular file"));
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "outside\n");
        assert!(!db_path.exists());
    }

    /// A cache database deliberately placed outside `.bifrost/cache` (the
    /// `BIFROST_CACHE_DIR` escape hatch, and every temp-dir test above) must not
    /// get a `.gitignore` dropped into it.
    #[test]
    fn non_cache_directories_do_not_get_a_self_ignore() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());

        let _conn = open_unified_connection(&db_path).unwrap();
        assert!(!temp.path().join(".gitignore").exists());
    }
}
