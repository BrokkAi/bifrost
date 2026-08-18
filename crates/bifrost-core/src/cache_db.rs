//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

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

/// The version the baseline script creates. Versions below it are gone: the
/// migrations that produced them were folded into the baseline, so a store
/// older than this cannot be carried forward and is refused.
const BASELINE_MIGRATION_VERSION: i64 = 18;
const CURRENT_MIGRATION_VERSION: i64 = 23;
pub const OPTIONAL_FACT_KIND_CPP_TEMPLATE_METADATA: i64 = 1;
pub const OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE: i64 = 2;
pub const OPTIONAL_FACT_KIND_SCALA_TRAIT: i64 = 3;
pub const OPTIONAL_FACT_KIND_SCALA_EXPORT: i64 = 4;
pub const OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD: i64 = 5;
const BASELINE_CACHE_STATE_VERSIONS: (i64, i64, i64) = (1, 1, 10);
const CURRENT_BASELINE_SQL: &str = include_str!("../migrations/cache/0018-current-baseline.sql");
const IMPORT_BINDINGS_SQL: &str = include_str!("../migrations/cache/0019-import-bindings.sql");
const RUST_INCLUDE_EDGES_SQL: &str =
    include_str!("../migrations/cache/0020-rust-include-edges.sql");
const RUST_IMPORT_CFG_AND_EXTERN_CRATE_SQL: &str =
    include_str!("../migrations/cache/0021-rust-import-cfg-and-extern-crate.sql");
const DROP_BM25_LEXICAL_COLUMNS_SQL: &str =
    include_str!("../migrations/cache/0022-drop-bm25-lexical-columns.sql");
const SIGNATURE_METADATA_COLUMNS_SQL: &str =
    include_str!("../migrations/cache/0023-signature-metadata-columns.sql");

// Migration 0023 spells the signature-metadata byte cap as the literal 8388608,
// because a checked-in SQL file cannot interpolate a Rust constant. The two must
// stay equal or the schema stops enforcing the budget the store believes in.
const _: () = assert!(crate::analyzer::model::MAX_SIGNATURE_METADATA_COLUMN_BYTES == 8_388_608);
/// One migration and the schema version a store holds once it has run.
///
/// The version is carried explicitly rather than inferred from the entry's
/// position. Position and version stopped agreeing when migrations 1..18 were
/// folded into one baseline script: the list has five entries and the newest
/// version is 22. Inferring the version from an index is what let a merge
/// renumber a shipped schema silently once already (see
/// [`RECOGNIZED_FOREIGN_STORES`]), so the number a store will carry is now
/// written down beside the SQL that gives it that schema.
#[derive(Clone, Copy)]
struct CacheMigration {
    version: i64,
    sql: &'static str,
}

const CACHE_MIGRATIONS: [CacheMigration; 6] = [
    CacheMigration {
        version: 18,
        sql: CURRENT_BASELINE_SQL,
    },
    CacheMigration {
        version: 19,
        sql: IMPORT_BINDINGS_SQL,
    },
    CacheMigration {
        version: 20,
        sql: RUST_INCLUDE_EDGES_SQL,
    },
    CacheMigration {
        version: 21,
        sql: RUST_IMPORT_CFG_AND_EXTERN_CRATE_SQL,
    },
    CacheMigration {
        version: 22,
        sql: DROP_BM25_LEXICAL_COLUMNS_SQL,
    },
    CacheMigration {
        version: 23,
        sql: SIGNATURE_METADATA_COLUMNS_SQL,
    },
];

// The store file is named for the schema version that wrote it, so the list
// above and the two version constants must agree or a build ships a file name
// that lies about its schema. The invariant is no longer "one entry per
// version" -- the baseline stands for eighteen of them -- so assert what is
// actually true: the first entry produces the baseline version, the last
// produces the current one, and the versions strictly increase in between.
const _: () = assert!(CACHE_MIGRATIONS[0].version == BASELINE_MIGRATION_VERSION);
const _: () =
    assert!(CACHE_MIGRATIONS[CACHE_MIGRATIONS.len() - 1].version == CURRENT_MIGRATION_VERSION);
const _: () = {
    let mut index = 1;
    while index < CACHE_MIGRATIONS.len() {
        assert!(CACHE_MIGRATIONS[index - 1].version < CACHE_MIGRATIONS[index].version);
        index += 1;
    }
};

static CACHE_DB_FILE_NAME: Lazy<String> =
    Lazy::new(|| cache_db_file_name_for_version(CURRENT_MIGRATION_VERSION));
static BASELINE_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open baseline schema connection");
    conn.execute_batch(CURRENT_BASELINE_SQL)
        .expect("create baseline schema");
    schema_object_definitions(&conn).expect("read baseline schema definitions")
});
/// The schema every migration in [`CACHE_MIGRATIONS`] produces in order.
///
/// This is what a store must look like to be this build's, whether it was
/// created here or carried forward from an older one
/// ([`verify_upgraded_store`]).
static CURRENT_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open current schema connection");
    for migration in &CACHE_MIGRATIONS {
        conn.execute_batch(migration.sql)
            .unwrap_or_else(|err| panic!("apply cache migration {}: {err}", migration.version));
    }
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
    // An older store is optional input. When it cannot be carried forward the
    // operator needs to know -- a cold start on an indexed corpus is hours of
    // re-embedding -- but a neighbouring file this build cannot read must not
    // be what stops the workspace from opening at all.
    if let Err(error) = import_newest_older_store(&db_path) {
        eprintln!("Bifrost cache upgrade skipped, starting a fresh store: {error}");
    }
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
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = Connection::open_with_flags(
        &db_path,
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

/// Page cache for one interactive reader connection, in KiB (negative = KiB,
/// SQLite's convention). Every pooled reader pays this, so the resident cost is
/// this value times the number of retained connections, not once per process.
///
/// 8 MiB is four times SQLite's ~2 MB default and holds the b-tree interior
/// pages and index roots that the post-campaign read mix (indexed point seeks
/// into `code_units` and the parsed-blob tables) touches repeatedly. The
/// previous value, 64 MiB, was chosen as if there were one reader; measured on
/// 2026-08-08 against 120 pooled readers it contributed 1.32-2.82 GB with a
/// 7.68 GB ceiling.
///
/// Both directions are measured on the same cell (2026-08-08). Holding the
/// other two knobs fixed, 64 MiB against 8 MiB is 225.3 against 218.4
/// CPU-seconds (`sys` 85.4 against 86.1) -- i.e. free -- and 8 MiB carries
/// 131 MB less private memory. Going further, to the streaming path's 2 MiB,
/// cost 20-30% more CPU on the larger tree the earlier ladder used (248.9
/// against 187.1 CPU-seconds), nearly all `sys`, from re-reading evicted pages.
const READER_PAGE_CACHE_KIB: i64 = -8192;

fn configure_readonly_page_cache(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", READER_PAGE_CACHE_KIB)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    // No memory-mapped I/O. `mmap_size` is per connection, so a pool of readers
    // maps the same file once each, and the mapped bytes scale with the host's
    // core count as well as the DB: measured 2026-08-08, 115-125 mappings of one
    // 176 MB cache DB held 20.0 GB of mapped address space for a whole query.
    // mmap's only unique benefit is avoiding a copy out of the OS page cache,
    // which matters when the DB does not fit the connection's own cache --
    // exactly the case where the mapping cost is largest.
    //
    // This is a priced trade, not a free win. Isolated on the same cell,
    // removing the mapping costs about 7% CPU, all of it `sys` (212.2 against
    // 197.6 CPU-seconds; `sys` 79.6 against 70.1) from read syscalls replacing
    // mapped loads, and wall clock does not move. It buys 20.0 GB of address
    // space and 2.3 GB of RSS back, and it removes a ceiling that grows with
    // both the DB size and the core count (5.55-12.3 GB on the 848 MB rustc
    // cache, ~30 GB worst case on a 120-CPU host).
    // `open_streaming_readonly_connection` already reached this conclusion for
    // scans; it holds for interactive readers too.
    conn.pragma_update(None, "mmap_size", 0)
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
/// extracted -- for a semantically indexed corpus, hours of GPU embedding for
/// vectors that are already on disk and still valid. Copy the newest store this
/// build can migrate forward instead, carry the copy the rest of the way with
/// the ordinary migration machinery, and publish it only once it has arrived.
///
/// The source is only ever read. An older checkout keeps opening it, the
/// existence of a newer file says nothing about whether the older one is still
/// live (issue #1589), and the version sweeper reclaims it once it has gone
/// [`VERSION_STORE_GRACE_SECS`] unused. Renaming instead of copying would save
/// a transient doubling of one store's bytes and cost exactly the guarantee
/// #1589 was filed to establish.
///
/// The copy goes through SQLite's backup API rather than the filesystem
/// because a live source holds committed pages in its `-wal` sidecar; copying
/// the main file alone would silently drop them.
fn import_newest_older_store(db_path: &Path) -> Result<()> {
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return Ok(());
    }
    // A store this build owns already exists. It wins unconditionally: a
    // downgrade-then-upgrade session must never let an older store overwrite
    // the newer data written since.
    if db_path.exists() {
        return Ok(());
    }
    let cache_dir = db_path
        .parent()
        .expect("a prepared cache DB path has a parent directory");
    let Some(source) = newest_importable_store(cache_dir)? else {
        return Ok(());
    };
    let upgraded = stage_upgraded_store(cache_dir, &source)?;
    match upgraded.persist_noclobber(db_path) {
        Ok(()) => {
            eprintln!(
                "Bifrost cache upgraded {} to schema version {} as {}",
                source.display(),
                CURRENT_MIGRATION_VERSION,
                db_path.display()
            );
            Ok(())
        }
        // Another process published its own upgrade first. It drew from the
        // same candidate set, so ours has nothing to add.
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(format!(
            "failed to atomically publish upgraded cache DB {}: {}",
            db_path.display(),
            err.error
        )),
    }
}

/// Copy `source` aside, migrate the copy to this build's schema, and prove the
/// result before anyone can see it.
///
/// Publishing first and migrating afterwards is what made a failed upgrade
/// unrecoverable: the half-migrated copy already carried this build's file
/// name, so every later open found the file present, skipped the upgrade, and
/// failed the same migration again. Nothing here is visible under that name
/// until the migration has run, the schema matches this build's exactly, and
/// `quick_check` passes; a failure drops the staged path and leaves the source
/// untouched.
fn stage_upgraded_store(cache_dir: &Path, source: &Path) -> Result<tempfile::TempPath> {
    let staged = tempfile::Builder::new()
        .prefix(".bifrost-cache-import")
        .tempfile_in(cache_dir)
        .map_err(|err| format!("failed to stage cache DB upgrade: {err}"))?
        // Release the handle. SQLite owns the path from here; the guard only
        // keeps the deletion-on-drop that makes a failed upgrade leave nothing.
        .into_temp_path();
    {
        let source_conn = Connection::open_with_flags(
            source,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|err| {
            format!(
                "cache DB upgrade SQLite error reading {}: {err}",
                source.display()
            )
        })?;
        source_conn
            .backup(rusqlite::DatabaseName::Main, &staged, None)
            .map_err(|err| {
                format!(
                    "cache DB upgrade SQLite error copying {}: {err}",
                    source.display()
                )
            })?;
    }
    let mut conn = Connection::open_with_flags(
        &staged,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB upgrade SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    refuse_store_below_baseline(&conn, source)?;
    adopt_store_schema_version(&mut conn, source)?;
    migrate(&mut conn)?;
    verify_upgraded_store(&conn, source)?;
    drop(conn);
    Ok(staged)
}

/// The upgraded copy must be indistinguishable from a store this build wrote.
///
/// A migration that merely does not raise is not proof. Version numbers are
/// per-lineage counters (see [`RECOGNIZED_FOREIGN_STORES`]), so a store can
/// declare a version whose migrations happen to apply without producing this
/// build's schema. Compare the whole schema, then let SQLite check the pages.
fn verify_upgraded_store(conn: &Connection, source: &Path) -> Result<()> {
    let version = cache_migration_version(conn)?;
    if version != CURRENT_MIGRATION_VERSION {
        return Err(format!(
            "cache DB upgrade of {} reached schema version {version}, not {CURRENT_MIGRATION_VERSION}",
            source.display()
        ));
    }
    let objects = schema_object_definitions(conn)?;
    if objects != *CURRENT_SCHEMA_OBJECTS {
        let migrated: HashSet<&str> = objects.iter().map(|(_, name, _)| name.as_str()).collect();
        let expected: HashSet<&str> = CURRENT_SCHEMA_OBJECTS
            .iter()
            .map(|(_, name, _)| name.as_str())
            .collect();
        return Err(format!(
            "cache DB upgrade of {} did not reproduce this build's schema; \
             objects only in the upgrade: {:?}; objects only in this build: {:?}",
            source.display(),
            migrated.difference(&expected).collect::<Vec<_>>(),
            expected.difference(&migrated).collect::<Vec<_>>(),
        ));
    }
    if !quick_check_is_ok(conn)? {
        return Err(format!(
            "cache DB upgrade of {} failed quick_check",
            source.display()
        ));
    }
    Ok(())
}

/// A store older than the baseline cannot be carried forward.
///
/// The migrations that produced those versions were folded into the baseline
/// script, which creates a schema rather than upgrading one into place. Left
/// to run, [`migrate`] would find the store's schema unrecognizable, rebuild
/// it empty, and publish that as the upgrade -- a cold start wearing the
/// carried-forward store's name. Say so and decline instead. `migrate` keeps
/// its own behaviour for a store already under this build's name, where
/// rebuilding a damaged file is the only way to open the workspace at all.
fn refuse_store_below_baseline(conn: &Connection, source: &Path) -> Result<()> {
    let version = cache_migration_version(conn)?;
    if version > 0 && version < BASELINE_MIGRATION_VERSION {
        return Err(format!(
            "cache DB {} is at schema version {version}, which predates this build's baseline \
             {BASELINE_MIGRATION_VERSION}; the migrations that produced it are no longer shipped, \
             so it cannot be carried forward",
            source.display(),
        ));
    }
    Ok(())
}

/// A schema this build recognizes but cannot name with its own version number.
///
/// A cache store's `user_version` is a count of the migrations its build had,
/// not an identity for the schema they produced. Two branches that both add
/// migrations mint the same numbers for different schemas, and merging them
/// renumbers one side. That is not hypothetical: `bifrost-nlp-ft` shipped
/// `import-bindings` as its migration 18, then merged master, which inserted
/// `0016-optional-fact-manifest` beneath three migrations the branch had
/// already shipped and pushed `import-bindings` to 19. Stores written by that
/// branch -- among them the CodeScaleBench r26 evaluation caches, 5.5 million
/// embedded chunks -- declare version 18 while holding this build's version 19
/// schema minus migration 16. Running this build's 19 over one of them fails on
/// `DROP TABLE import_details`, a table that store never had.
///
/// Recognition is by a discriminating predicate rather than a stored schema
/// snapshot: the snapshot would be a second copy of the schema to keep true,
/// and the squash of 0001..0018 into one baseline removed the ability to
/// synthesize the shape from the chain in any case.
struct RecognizedForeignStore {
    /// What the store's `user_version` claims.
    declared_version: i64,
    /// True for exactly this lineage's stores at [`Self::declared_version`].
    recognize: fn(&Connection) -> Result<bool>,
    /// Brings the store to [`Self::equivalent_version`] of this build's chain.
    bridge_sql: &'static str,
    /// The version of this build's chain the bridged store then holds.
    equivalent_version: i64,
    /// Named in the log line so an operator can tell which rule fired.
    lineage: &'static str,
}

/// The bridge is `0016-optional-fact-manifest.sql` with the one column that
/// migration 19 had already dropped removed from its `blob_meta` rebuild. It
/// cannot be shared with migration 16 itself, which still runs before 19 for
/// every store in this build's own lineage.
const OPTIONAL_FACT_MANIFEST_AFTER_IMPORT_BINDINGS_SQL: &str =
    include_str!("../migrations/cache/bridges/0016-optional-fact-manifest-after-19.sql");

const RECOGNIZED_FOREIGN_STORES: [RecognizedForeignStore; 1] = [RecognizedForeignStore {
    declared_version: 18,
    recognize: is_nlp_ft_import_bindings_store,
    bridge_sql: OPTIONAL_FACT_MANIFEST_AFTER_IMPORT_BINDINGS_SQL,
    equivalent_version: 19,
    lineage: "bifrost-nlp-ft import-bindings-at-18",
}];

/// The `bifrost-nlp-ft` version 18 store: migration 19's `import_statements`
/// is present, and migration 16's manifest table is not.
///
/// Both halves are needed. The first alone also matches this build's version 19
/// and later; the second alone also matches this build's version 15 and
/// earlier. Together they describe a schema no version of this build's own
/// chain ever produced.
fn is_nlp_ft_import_bindings_store(conn: &Connection) -> Result<bool> {
    Ok(column_exists(conn, "import_statements", "is_wildcard")?
        && !table_exists(conn, "blob_optional_fact_manifest")?)
}

/// Give the staged copy a version number that means what this build's
/// migrations expect it to mean.
///
/// The ordinary case needs nothing: a store from this build's own lineage
/// declares a version this build's chain also produced, so its pending
/// migrations are exactly the ones after it. Only a recognized foreign lineage
/// is rewritten, and only onto the version of this chain whose schema it then
/// holds. An unrecognized shape is left alone deliberately: the migrations run
/// against it, and [`verify_upgraded_store`] rejects the result if they did not
/// produce this build's schema.
fn adopt_store_schema_version(conn: &mut Connection, source: &Path) -> Result<()> {
    let declared_version = cache_migration_version(conn)?;
    for foreign in &RECOGNIZED_FOREIGN_STORES {
        if declared_version != foreign.declared_version || !(foreign.recognize)(conn)? {
            continue;
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|err| format!("cache DB upgrade SQLite error: {err}"))?;
        tx.execute_batch(foreign.bridge_sql).map_err(|err| {
            format!(
                "cache DB upgrade error bridging {} from the {} lineage: {err}",
                source.display(),
                foreign.lineage
            )
        })?;
        tx.pragma_update(None, "user_version", foreign.equivalent_version)
            .map_err(|err| format!("cache DB upgrade SQLite error: {err}"))?;
        tx.commit()
            .map_err(|err| format!("cache DB upgrade SQLite error: {err}"))?;
        eprintln!(
            "Bifrost cache upgrade: {} declares schema version {declared_version} from the {} \
             lineage, which is this build's version {}; bridged and continuing",
            source.display(),
            foreign.lineage,
            foreign.equivalent_version,
        );
        return Ok(());
    }
    Ok(())
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
    migrate_with_sql(conn, &CACHE_MIGRATIONS)
}

fn migrate_with_sql(conn: &mut Connection, migrations: &[CacheMigration]) -> Result<()> {
    let user_version = cache_migration_version(conn)?;
    if current_schema_fast_path(migrations, user_version)
        && current_schema_claim_is_valid(conn, migrations, user_version)?
    {
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
    migrations: &[CacheMigration],
    rebuild_invalid_schema: bool,
) -> Result<LockedMigrationOutcome> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let mut user_version = cache_migration_version(&tx)?;
    if user_version < 0 {
        return Err(format!(
            "cache DB migration user_version must not be negative: {user_version}"
        ));
    }
    let newest_version = migrations
        .last()
        .expect("the migration list is never empty")
        .version;
    if user_version > newest_version {
        // Version skew no longer reaches here: a build opens only the store
        // named for its own schema, and imports from an older one instead of
        // migrating it (issue #1589). A file whose name claims this schema and
        // whose user_version claims a later one is corrupt, so say what to do
        // with it rather than leaving the workspace unopenable.
        return Err(format!(
            "cache DB migration error: DatabaseTooFarAhead: user_version {user_version} exceeds {newest_version} in {}. \
             Each schema version has its own store file, so this file's contents contradict its name; \
             moving it aside is safe and this build will import the newest compatible older store or \
             start a fresh one.",
            tx.path().unwrap_or("<in-memory>"),
        ));
    }
    if current_schema_fast_path(migrations, user_version) {
        if current_schema_claim_is_valid(&tx, migrations, user_version)? {
            tx.commit()
                .map_err(|err| format!("cache DB migration fast-path commit error: {err}"))?;
            return Ok(LockedMigrationOutcome::Complete);
        }
        if !rebuild_invalid_schema {
            return Ok(LockedMigrationOutcome::RebuildRequired);
        }
        recreate_schema(&tx)?;
        user_version = 0;
    }

    let user_version = match prepare_baseline_migration(&tx, user_version, rebuild_invalid_schema)?
    {
        BaselinePreparation::Ready(user_version) => user_version,
        BaselinePreparation::RebuildRequired => {
            return Ok(LockedMigrationOutcome::RebuildRequired);
        }
    };
    let mut migration_applied = false;
    for migration in migrations
        .iter()
        .filter(|migration| migration.version > user_version)
    {
        let version = migration.version;
        tx.execute_batch(migration.sql)
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

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))
}

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

fn current_schema_shape_is_valid(conn: &Connection) -> Result<bool> {
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

#[cfg(test)]
fn current_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    current_schema_shape_is_valid(conn)
}

/// Nothing is pending, so skip taking the write lock.
///
/// Identity of the list is deliberately not part of this test. A `const` is
/// inlined at each use, so two mentions of `CACHE_MIGRATIONS` need not share an
/// address, and a pointer comparison would quietly never hold -- costing every
/// open a write lock it does not need. What matters is the question actually
/// being asked: is the store already at the newest version these migrations
/// produce.
fn current_schema_fast_path(migrations: &[CacheMigration], user_version: i64) -> bool {
    migrations
        .last()
        .is_some_and(|migration| migration.version == user_version)
}

/// Validate the schema interface when this build's own version number claims
/// that no migration is pending.
///
/// `migrate_with_sql` also builds historical and synthetic future schemas in
/// tests, so their terminal versions retain the generic version-only fast
/// path. The production current schema gets the stronger check. Comparing
/// `sqlite_master` and the singleton version row is bounded by the schema size;
/// do not run `quick_check` here because that would scan a potentially huge
/// cache on every workspace open.
fn current_schema_claim_is_valid(
    conn: &Connection,
    migrations: &[CacheMigration],
    user_version: i64,
) -> Result<bool> {
    debug_assert!(current_schema_fast_path(migrations, user_version));
    if user_version != CURRENT_MIGRATION_VERSION {
        return Ok(true);
    }
    current_schema_shape_is_valid(conn)
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

    /// This build's migrations plus one more, standing for the next schema
    /// version a future build will add.
    fn future_migration_sql(sql: &'static str) -> Vec<CacheMigration> {
        CACHE_MIGRATIONS
            .into_iter()
            .chain(std::iter::once(CacheMigration {
                version: CURRENT_MIGRATION_VERSION + 1,
                sql,
            }))
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
        conn.execute_batch("DROP TABLE semantic_vectors;").unwrap();
        conn.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
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
        assert!(
            !table_exists(&conn, "rust_include_edges").unwrap(),
            "a table a rolled-back migration created must be gone with it"
        );
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

    // -----------------------------------------------------------------------
    // Carrying an older store forward (issue #1589's upgrade path).
    //
    // The expensive thing in a warm cache is the semantic index: a large
    // corpus is hours of GPU embedding. These tests use semantic rows as the
    // payload because they are the rows whose loss actually costs something.
    // -----------------------------------------------------------------------

    /// Zero, one, and many: enough rows to prove a copy rather than a shape.
    const SEEDED_CHUNKS: [(&str, &str, i64); 3] = [
        ("a.py", "alpha", 0),
        ("a.py", "beta", 1),
        ("nested/b.py", "gamma", 0),
    ];

    /// A 40-character lowercase-hex OID and a 32-byte vector key, derived from
    /// `name` so the fixtures stay readable and the CHECK constraints hold.
    fn seeded_oid(name: &str) -> String {
        let mut oid: String = name.bytes().map(|byte| format!("{byte:02x}")).collect();
        oid.truncate(40);
        while oid.len() < 40 {
            oid.push('0');
        }
        oid
    }

    fn seeded_vector_hash(name: &str) -> Vec<u8> {
        let mut key = name.as_bytes().to_vec();
        key.resize(32, 0);
        key
    }

    /// Create a store at `path` holding exactly `migrations`, then stamp
    /// `user_version`.
    ///
    /// The stamp is a parameter because a store's version number is a count of
    /// its own build's migrations, which is not always the count applied here:
    /// that mismatch is the whole subject of
    /// [`nlp_ft_lineage_v18_store_is_bridged_and_carried_forward`].
    fn create_store_at(path: &Path, migrations: &[CacheMigration], user_version: i64) {
        let mut conn = Connection::open(path).unwrap();
        configure_connection(&mut conn).unwrap();
        migrate_with_sql(&mut conn, migrations).unwrap();
        conn.pragma_update(None, "user_version", user_version)
            .unwrap();
        seed_semantic_rows(&conn);
    }

    fn seed_semantic_rows(conn: &Connection) {
        // Before migration 22 the chunk row also carried the BM25 tokens, and
        // the column is NOT NULL. Seeding a pre-22 store means writing it; the
        // upgrade then drops it, which is exactly what must not disturb the
        // rest of the row.
        let with_fts = column_exists(conn, "semantic_file_chunks", "fts_tokens").unwrap();
        for (rel_path, symbol, chunk_ord) in SEEDED_CHUNKS {
            let blob_oid = seeded_oid(rel_path);
            let vector_hash = seeded_vector_hash(symbol);
            conn.execute(
                "INSERT OR IGNORE INTO semantic_files(blob_oid, rel_path, language)
                 VALUES (?1, ?2, 'python')",
                rusqlite::params![blob_oid, rel_path],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO semantic_vectors(vector_hash, dim, vector)
                 VALUES (?1, 4, ?2)",
                rusqlite::params![vector_hash, symbol.as_bytes()],
            )
            .unwrap();
            if with_fts {
                conn.execute(
                    "INSERT INTO semantic_file_chunks(
                         blob_oid, rel_path, chunk_ord, symbol, start_line, end_line,
                         vector_hash, fts_tokens)
                     VALUES (?1, ?2, ?3, ?4, 1, 9, ?5, ?6)",
                    rusqlite::params![blob_oid, rel_path, chunk_ord, symbol, vector_hash, symbol],
                )
                .unwrap();
            } else {
                conn.execute(
                    "INSERT INTO semantic_file_chunks(
                         blob_oid, rel_path, chunk_ord, symbol, start_line, end_line, vector_hash)
                     VALUES (?1, ?2, ?3, ?4, 1, 9, ?5)",
                    rusqlite::params![blob_oid, rel_path, chunk_ord, symbol, vector_hash],
                )
                .unwrap();
            }
        }
    }

    /// Every seeded chunk with the vector bytes it points at, in a stable
    /// order. Equality of this against the pre-upgrade value is the claim that
    /// no embedding has to be recomputed.
    fn semantic_rows(conn: &Connection) -> Vec<(String, String, i64, String, Vec<u8>)> {
        let mut statement = conn
            .prepare(
                "SELECT chunks.rel_path, chunks.symbol, chunks.chunk_ord,
                        files.language, vectors.vector
                 FROM semantic_file_chunks AS chunks
                 JOIN semantic_files AS files
                   ON files.blob_oid = chunks.blob_oid AND files.rel_path = chunks.rel_path
                 JOIN semantic_vectors AS vectors
                   ON vectors.vector_hash = chunks.vector_hash
                 ORDER BY chunks.rel_path, chunks.chunk_ord",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn read_semantic_rows(path: &Path) -> Vec<(String, String, i64, String, Vec<u8>)> {
        semantic_rows(&Connection::open(path).unwrap())
    }

    fn store_path(cache_dir: &Path, version: i64) -> PathBuf {
        cache_dir.join(cache_db_file_name_for_version(version))
    }

    fn current_store_path(cache_dir: &Path) -> PathBuf {
        cache_dir.join(cache_db_file_name())
    }

    fn staged_leftovers(cache_dir: &Path) -> Vec<String> {
        std::fs::read_dir(cache_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".bifrost-cache-import"))
            .collect()
    }

    /// The migrations that bring a store to `version`.
    fn migrations_through(version: i64) -> Vec<CacheMigration> {
        CACHE_MIGRATIONS
            .into_iter()
            .filter(|migration| migration.version <= version)
            .collect()
    }

    /// Undo what migration 16 did, so a fixture can stand where the
    /// `bifrost-nlp-ft` branch stood when it shipped its version 18.
    ///
    /// Migration 16 is inside the baseline now, so it can no longer be left
    /// out of a chain. Putting back the three counts it moved and dropping the
    /// table it added reaches the same place. The columns carry no CHECK
    /// because nothing reads them before the bridge rebuilds the table.
    const UNDO_OPTIONAL_FACT_MANIFEST_SQL: &str = "\
        ALTER TABLE blob_meta ADD COLUMN ruby_dispatch_count INTEGER NOT NULL DEFAULT 0;\
        ALTER TABLE blob_meta ADD COLUMN scala_trait_count INTEGER NOT NULL DEFAULT 0;\
        ALTER TABLE blob_meta ADD COLUMN cpp_template_metadata_count INTEGER NOT NULL DEFAULT 0;\
        DROP TABLE blob_optional_fact_manifest;";

    /// A store shaped the way `bifrost-nlp-ft` wrote one at its version 18:
    /// migration 19 applied, migration 16 not, and the number 18 on the front.
    fn create_nlp_ft_v18_store(path: &Path) {
        let mut conn = Connection::open(path).unwrap();
        configure_connection(&mut conn).unwrap();
        migrate_with_sql(&mut conn, &migrations_through(18)).unwrap();
        conn.execute_batch(UNDO_OPTIONAL_FACT_MANIFEST_SQL).unwrap();
        conn.execute_batch(IMPORT_BINDINGS_SQL).unwrap();
        conn.pragma_update(None, "user_version", 18).unwrap();
        seed_semantic_rows(&conn);
    }

    /// The ordinary upgrade: a store from this build's own lineage, one
    /// version back, is carried forward with its rows and its source kept.
    #[test]
    fn an_older_store_is_carried_forward_with_its_semantic_rows() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path();
        let previous = CURRENT_MIGRATION_VERSION - 1;
        let older = store_path(cache_dir, previous);
        create_store_at(&older, &migrations_through(previous), previous);
        let expected = read_semantic_rows(&older);
        let older_before = std::fs::read(&older).unwrap();

        let conn = open_unified_connection(&current_store_path(cache_dir)).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            semantic_rows(&conn),
            expected,
            "every embedded chunk must survive the upgrade unchanged"
        );
        assert!(quick_check_is_ok(&conn).unwrap());
        assert_eq!(
            std::fs::read(&older).unwrap(),
            older_before,
            "the source stays readable for the checkouts still on it (issue #1589)"
        );
        assert!(staged_leftovers(cache_dir).is_empty());
    }

    /// A `bifrost-nlp-ft` store declares version 18 while holding this build's
    /// version 19 schema minus migration 16. Its pending migrations are
    /// therefore not "19 onwards", and running 19 over it fails on `DROP TABLE
    /// import_details`.
    ///
    /// Fail-before: without [`RECOGNIZED_FOREIGN_STORES`] this test fails with
    /// that error, the upgrade is abandoned, and the assertions below see an
    /// empty store beside an ignored 248 MB one.
    #[test]
    fn nlp_ft_lineage_v18_store_is_bridged_and_carried_forward() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path();
        let foreign = store_path(cache_dir, 18);
        create_nlp_ft_v18_store(&foreign);
        let expected = read_semantic_rows(&foreign);
        assert_eq!(expected.len(), SEEDED_CHUNKS.len());
        let foreign_before = std::fs::read(&foreign).unwrap();

        let conn = open_unified_connection(&current_store_path(cache_dir)).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            semantic_rows(&conn),
            expected,
            "the vectors this upgrade exists to save must arrive byte for byte"
        );
        assert_eq!(
            schema_object_definitions(&conn).unwrap(),
            *CURRENT_SCHEMA_OBJECTS,
            "a bridged store must be indistinguishable from one this build wrote"
        );
        assert!(quick_check_is_ok(&conn).unwrap());
        assert_eq!(std::fs::read(&foreign).unwrap(), foreign_before);
    }

    /// The recognizer has to be exact: both halves of the predicate matter, so
    /// this build's own version 18 store must not be mistaken for the foreign
    /// one and bridged.
    #[test]
    fn this_builds_own_v18_store_is_not_mistaken_for_the_foreign_lineage() {
        let conn = {
            let mut conn = Connection::open_in_memory().unwrap();
            configure_connection(&mut conn).unwrap();
            migrate_with_sql(&mut conn, &migrations_through(18)).unwrap();
            conn
        };

        assert!(
            !is_nlp_ft_import_bindings_store(&conn).unwrap(),
            "this build's version 18 has migration 16's manifest table"
        );

        let temp = tempfile::tempdir().unwrap();
        let foreign_path = temp.path().join("foreign.db");
        create_nlp_ft_v18_store(&foreign_path);
        let foreign = Connection::open(&foreign_path).unwrap();
        assert!(is_nlp_ft_import_bindings_store(&foreign).unwrap());
    }

    /// A store this build already owns wins over any older one. A session that
    /// downgraded and came back must not lose the rows written in between.
    #[test]
    fn an_existing_current_store_wins_and_the_older_one_is_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path();
        let older = store_path(cache_dir, CURRENT_MIGRATION_VERSION - 1);
        create_store_at(
            &older,
            &migrations_through(CURRENT_MIGRATION_VERSION - 1),
            CURRENT_MIGRATION_VERSION - 1,
        );
        let older_before = std::fs::read(&older).unwrap();
        let current = current_store_path(cache_dir);
        {
            let mut conn = Connection::open(&current).unwrap();
            configure_connection(&mut conn).unwrap();
            migrate(&mut conn).unwrap();
            conn.execute(
                "INSERT INTO semantic_vectors(vector_hash, dim, vector) VALUES (?1, 4, X'01')",
                [seeded_vector_hash("written after the downgrade")],
            )
            .unwrap();
        }

        let conn = open_unified_connection(&current).unwrap();

        let vectors: i64 = conn
            .query_row("SELECT count(*) FROM semantic_vectors", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            vectors, 1,
            "the older store must not overwrite the current one"
        );
        assert_eq!(std::fs::read(&older).unwrap(), older_before);
    }

    /// A source that cannot be carried forward must cost the workspace a cold
    /// start and nothing else: the open still succeeds, the source is intact,
    /// and no unusable file is left under this build's name for the next
    /// process to trip over.
    #[test]
    fn an_unusable_older_store_leaves_the_source_intact_and_still_opens() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path();
        let poisoned = store_path(cache_dir, CURRENT_MIGRATION_VERSION - 1);
        {
            let mut conn = Connection::open(&poisoned).unwrap();
            configure_connection(&mut conn).unwrap();
            migrate_with_sql(
                &mut conn,
                &migrations_through(CURRENT_MIGRATION_VERSION - 1),
            )
            .unwrap();
            // The table the last migration is about to drop is already gone, so
            // that migration cannot run and no bridge claims this shape. This
            // statement must keep tracking whatever the newest migration
            // rewrites; a poison aimed at an older migration would let the
            // upgrade succeed and the test would prove nothing.
            conn.execute_batch("DROP TABLE unit_signature_metadata;")
                .unwrap();
        }
        let poisoned_before = std::fs::read(&poisoned).unwrap();

        let conn = open_unified_connection(&current_store_path(cache_dir)).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        let vectors: i64 = conn
            .query_row("SELECT count(*) FROM semantic_vectors", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(vectors, 0, "a failed upgrade starts cold, it does not lie");
        assert_eq!(
            std::fs::read(&poisoned).unwrap(),
            poisoned_before,
            "a failed upgrade must not touch the source"
        );
        assert!(
            staged_leftovers(cache_dir).is_empty(),
            "the staged copy must be dropped, not left for the next open to adopt"
        );
    }

    /// A store older than the baseline is declined, not silently rebuilt into
    /// an empty store wearing this build's name.
    #[test]
    fn a_store_below_the_baseline_is_declined_and_left_alone() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path();
        let ancient = store_path(cache_dir, BASELINE_MIGRATION_VERSION - 1);
        create_store_at(&ancient, &CACHE_MIGRATIONS, CURRENT_MIGRATION_VERSION);
        {
            let conn = Connection::open(&ancient).unwrap();
            conn.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION - 1)
                .unwrap();
        }
        let ancient_before = std::fs::read(&ancient).unwrap();

        let conn = open_unified_connection(&current_store_path(cache_dir)).unwrap();

        let vectors: i64 = conn
            .query_row("SELECT count(*) FROM semantic_vectors", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(vectors, 0, "nothing below the baseline may be carried");
        assert_eq!(std::fs::read(&ancient).unwrap(), ancient_before);
        assert!(staged_leftovers(cache_dir).is_empty());
    }

    /// Concurrent openers race for one upgrade. Publication is
    /// `persist_noclobber`, so the loser discards its own copy and opens the
    /// winner's; every thread must come back with the carried rows.
    #[test]
    fn concurrent_openers_publish_one_upgrade_and_all_serve_it() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let previous = CURRENT_MIGRATION_VERSION - 1;
        let older = store_path(&cache_dir, previous);
        create_store_at(&older, &migrations_through(previous), previous);
        let expected = read_semantic_rows(&older);
        let older_before = std::fs::read(&older).unwrap();

        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let cache_dir = cache_dir.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let conn = open_unified_connection(&current_store_path(&cache_dir)).unwrap();
                    (
                        cache_migration_version(&conn).unwrap(),
                        semantic_rows(&conn),
                    )
                })
            })
            .collect();

        for handle in handles {
            let (version, rows) = handle.join().unwrap();
            assert_eq!(version, CURRENT_MIGRATION_VERSION);
            assert_eq!(rows, expected, "every racing opener must serve the upgrade");
        }
        assert!(
            quick_check_is_ok(&Connection::open(current_store_path(&cache_dir)).unwrap()).unwrap()
        );
        assert_eq!(std::fs::read(&older).unwrap(), older_before);
        assert!(staged_leftovers(&cache_dir).is_empty());
    }
}
