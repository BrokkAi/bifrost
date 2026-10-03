//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, Weak};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

pub mod sql_profile;

use sql_profile::ConnectionRole;

pub type Result<T> = std::result::Result<T, String>;

/// Shared stem of every cache store file name.
const CACHE_DB_STEM: &str = "bifrost_cache";
/// The pre-versioning store name. Builds older than version-keyed naming open
/// this file in place, so a current build imports from it and never writes it.
pub const LEGACY_CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
#[cfg(test)]
const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub const LEGACY_ANALYZER_DB_FILE_NAME: &str = "analyzer_cache.db";
/// The store file and the SQLite sidecars that belong to it.
pub const STORE_FILE_SUFFIXES: [&str; 4] = ["", "-wal", "-shm", "-journal"];
const INITIAL_BUILD_LOCK_SUFFIX: &str = ".initial-build.lock";
const ALLOW_NETWORK_CACHE_ENV: &str = "BIFROST_ALLOW_UNSAFE_NETWORK_CACHE";

/// The version the baseline script creates. Versions below it are gone: the
/// migrations that produced them were folded into the baseline, so a store
/// older than this cannot be carried forward and is refused.
const BASELINE_MIGRATION_VERSION: i64 = 125;
// Version 25 belonged to a rejected local relational-key experiment. Skipping
// it prevents an old experimental v25 store from being mistaken for this
// schema; the version sequence is intentionally monotonic, not contiguous.
/// #2771 starts the native cache lineage from an empty store. Schema 125
/// distinguishes nominal and receiver projection outputs on qualified routes.
/// Once #2771 lands, this floor must not advance for compatible migrations.
const FIRST_NATIVE_CACHE_VERSION: i64 = 125;
const CURRENT_MIGRATION_VERSION: i64 = 138;
const _: () = assert!(CURRENT_MIGRATION_VERSION >= FIRST_NATIVE_CACHE_VERSION);
pub const OPTIONAL_FACT_KIND_CPP_CLASS_TEMPLATE: i64 = 1;
pub const OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE: i64 = 2;
pub const OPTIONAL_FACT_KIND_SCALA_TRAIT: i64 = 3;
pub const OPTIONAL_FACT_KIND_SCALA_EXPORT: i64 = 4;
pub const OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD: i64 = 5;
pub const OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE: i64 = 6;
const BASELINE_CACHE_STATE_VERSIONS: (i64, i64, i64) = (1, 1, 10);
const BASELINE_SCHEMA_SQL: &str = include_str!("../migrations/cache/0125-baseline.sql");

#[derive(Clone, Copy, PartialEq, Eq)]
struct CacheMigration {
    version: i64,
    sql: &'static str,
}

/// Compatible migrations after the schema 125 floor.
const POST_BASELINE_MIGRATIONS: &[CacheMigration] = &[
    CacheMigration {
        version: 126,
        sql: include_str!("../migrations/cache/0126-policy-evaluation-per-policy.sql"),
    },
    CacheMigration {
        version: 127,
        sql: include_str!("../migrations/cache/0127-source-seal-validation-in-writer.sql"),
    },
    CacheMigration {
        version: 128,
        sql: include_str!("../migrations/cache/0128-structural-facts-jsonb.sql"),
    },
    CacheMigration {
        version: 129,
        sql: include_str!("../migrations/cache/0129-native-go-context.sql"),
    },
    CacheMigration {
        version: 130,
        sql: include_str!("../migrations/cache/0130-native-jvm-context.sql"),
    },
    CacheMigration {
        version: 131,
        sql: include_str!("../migrations/cache/0131-native-binding-admission.sql"),
    },
    CacheMigration {
        version: 132,
        sql: include_str!("../migrations/cache/0132-native-pointer-transfers.sql"),
    },
    CacheMigration {
        version: 133,
        sql: include_str!("../migrations/cache/0133-native-address-operands.sql"),
    },
    CacheMigration {
        version: 134,
        sql: include_str!("../migrations/cache/0134-native-go-membership-digest.sql"),
    },
    CacheMigration {
        version: 135,
        sql: include_str!("../migrations/cache/0135-go-external-package-provenance.sql"),
    },
    CacheMigration {
        version: 136,
        sql: include_str!("../migrations/cache/0136-native-type-components.sql"),
    },
    CacheMigration {
        version: 137,
        sql: include_str!("../migrations/cache/0137-go-source-package-authority.sql"),
    },
    CacheMigration {
        version: 138,
        sql: include_str!("../migrations/cache/0138-python-runtime-providers.sql"),
    },
];

static CACHE_DB_FILE_NAME: Lazy<String> =
    Lazy::new(|| cache_db_file_name_for_version(CURRENT_MIGRATION_VERSION));
/// The schema produced by the floor plus every compatible later migration.
static CURRENT_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open current schema connection");
    conn.execute_batch(BASELINE_SCHEMA_SQL)
        .expect("create schema 125 baseline");
    for migration in POST_BASELINE_MIGRATIONS {
        conn.execute_batch(migration.sql)
            .expect("apply post-baseline cache migration");
    }
    schema_object_definitions(&conn).expect("read current schema definitions")
});
// SHA-256 of `schema_object_definitions` for the schema produced by every
// migration above. A current store validates its actual schema against this
// pinned identity without rebuilding all historical schemas in a second,
// in-memory database on every process start. The regression test below derives
// the value through SQLite and forces this constant to move with a migration.
const CURRENT_SCHEMA_OBJECTS_SHA256: [u8; 32] = [
    104, 127, 76, 58, 245, 29, 197, 104, 225, 71, 122, 72, 221, 198, 104, 86, 99, 159, 148, 52,
    151, 236, 243, 39, 187, 35, 58, 236, 69, 73, 201, 246,
];
pub const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);
// One primary-repository cache is intentionally shared by every linked worktree.
// Large repositories can therefore have several independent analyzer/semantic
// processes queue behind one legitimate writer during evaluation or IDE fanout.
// Five seconds was shorter than observed write transactions and converted
// ordinary serialization into a permanently failed semantic index. Keep SQLite
// as the cross-process arbiter, but give queued writers enough time to take their
// turn instead of requiring per-worktree database copies.
const BUSY_TIMEOUT: Duration = Duration::from_secs(120);
/// What a collection's own connections wait for the store's write lock.
///
/// The timeout above is deliberately twice the 60-second MCP request budget,
/// which is right for a writer whose caller is waiting for its result and
/// wrong for opportunistic collection: a sweep that queues behind a live
/// writer for two minutes while holding the analyzer-cache build lock turns
/// ordinary SQLite serialization into an unexplained request timeout (#3170).
/// A collection has nothing to deliver and no caller to disappoint, so it
/// waits briefly and collects on the next cadence instead.
const COLLECTION_BUSY_TIMEOUT: Duration = Duration::from_secs(3);
/// Per-connection prepared-statement cache capacity. rusqlite defaults to 16,
/// which is far too small for our query surface: `format!`-spliced predicates
/// and (now fixed-arity) `IN` lists produce dozens of distinct SQL shapes, and
/// a 16-slot cache thrashes, re-preparing/finalizing hot statements inside the
/// critical section.
///
/// 256 covers the statements one Rust reverse request cycles through on a
/// reader. A reverse rename of tract's `TractResult` (3,512 references in 552
/// files, 2026-09-25) ran 189 distinct statement texts at least 552 times
/// each, as often as there were candidate files. Under the earlier 64
/// entries, 157 of those cached
/// statements were evicted and prepared again, 84,685 fresh preparations in
/// one request. The bound is per connection and does not depend on the
/// workspace.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 256;
/// The page size the cache store uses and upgrades to. Every hot fact table is
/// `WITHOUT ROWID` keyed by a random 40-char blob_oid, so bulk inserts scatter
/// across the b-tree: at the SQLite default 4 KiB a cold self-workspace build
/// issues ~1.03 M 4 KiB write syscalls. 32 KiB pages cut that syscall count
/// ~12x (issue #2326 writer-stage profile).
const CACHE_PAGE_SIZE_BYTES: i64 = 32 * 1024;
/// Writer page cache ceiling (negative = KiB). Raised from 64 MiB so the
/// enlarged persist batches below keep their dirty pages cached until commit
/// instead of spilling mid-transaction (issue #2326 measured configuration).
const WRITER_PAGE_CACHE_KIB: i64 = -524288;
/// Retain at most two auto-checkpoint intervals after a successful checkpoint.
const WAL_JOURNAL_SIZE_LIMIT_BYTES: i64 = 128 * 1024 * 1024;
const WRITER_PAGE_CACHE_ENV: &str = "BIFROST_SQLITE_WRITER_CACHE_KIB";
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
    remove_version_stores(&stores)
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
        if version >= BASELINE_MIGRATION_VERSION
            && last_store_use_unix_seconds(&store)? + VERSION_STORE_GRACE_SECS > now
        {
            continue;
        }
        stores.push(store);
    }
    Ok(stores)
}

fn remove_version_stores(stores: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for store in stores {
        if delete_store_if_idle(store)? {
            removed.push(store.clone());
        }
    }
    Ok(removed)
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
/// The one door every analyzer-store connection in this process goes through.
///
/// SQLite's statement profile is installed per connection, so a second
/// `Connection::open_with_flags` on a store elsewhere in this file would be a
/// connection the ledger never sees. Keeping the open here makes that
/// impossible: the role is the open site's own, which is why it is an argument
/// rather than something the caller can forget.
fn open_store_connection(
    db_path: &Path,
    flags: OpenFlags,
    role: ConnectionRole,
) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(db_path, flags)?;
    sql_profile::install(&conn, role);
    Ok(conn)
}

/// The in-memory store [`crate::cache_db`]'s callers fall back to when no temp
/// file can back an ephemeral analyzer store. It has no path, so it cannot go
/// through [`open_store_connection`], and it is the only other way a process
/// reaches a store.
pub fn open_in_memory_store_connection() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    sql_profile::install(&conn, ConnectionRole::Ephemeral);
    Ok(conn)
}

pub fn open_unified_connection(db_path: &Path) -> Result<Connection> {
    disable_sqlite_memory_statistics();
    {
        let _scope = crate::profiling::scope("cache_db.validate_filesystem");
        validate_writable_cache_filesystem(db_path)?;
    }
    open_unified_connection_unclassified(db_path).map_err(|error| {
        match cache_write_denial(db_path) {
            Some(denied) => cache_permission_denied_message(db_path, &denied),
            None => error,
        }
    })
}

/// Open the workspace's shared cache database for a collection.
///
/// Identical to [`open_unified_connection`] except for how long the connection
/// waits when another process holds the write lock: see
/// [`COLLECTION_BUSY_TIMEOUT`]. Collection is the one writer that must yield
/// to the live session rather than queue in front of it.
pub fn open_collection_connection(db_path: &Path) -> Result<Connection> {
    let conn = open_unified_connection(db_path)?;
    conn.busy_timeout(COLLECTION_BUSY_TIMEOUT)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(conn)
}

/// Set to `1` to leave SQLite's memory statistics on for this process.
pub const MEMORY_STATISTICS_ENV: &str = "BIFROST_SQLITE_MEMORY_STATISTICS";

/// Whether this process leaves the statistics on, from the opt-in's value.
///
/// Exactly `1` turns them on. Anything else, including an unset variable, an
/// empty one and `true`, leaves the default: an opt-in that a typo could half
/// enable would make a measured run's numbers unreadable.
fn keeps_sqlite_memory_statistics(opt_in: Option<&std::ffi::OsStr>) -> bool {
    opt_in == Some(std::ffi::OsStr::new("1"))
}

/// Turn SQLite's process-global memory statistics off, once, before this
/// process opens its first connection.
///
/// `libsqlite3-sys` bundles SQLite with memory statistics enabled, so every
/// `sqlite3Malloc` and `sqlite3_free` takes one process-global mutex that all
/// connections share. That mutex is what a wide analyzer query runs into: a warm
/// `scan_usages` over the exposed-kotlin corpus on a 120-core host spent 37% of
/// its samples in `pthread_mutex_lock`/`unlock` beneath `sqlite3_step`,
/// `sqlite3_column_*` and `sqlite3Malloc`/`free`, with no Bifrost symbol above
/// 1% (#2883). The counters that mutex protects are readable only through
/// `sqlite3_memory_used`, `sqlite3_memory_highwater`, `sqlite3_status` and the
/// soft/hard heap limits. Bifrost calls none of those and sets no heap limit, so
/// here the statistics are pure overhead. A future SQLite memory budget has to
/// turn them back on in this same place, ahead of the first connection.
///
/// `sqlite3_config` is legal only while the library is uninitialized, and the
/// first connection open initializes it. There is no single `main` to hold this
/// -- Bifrost runs as a CLI, an MCP server, an LSP server, a benchmark harness
/// and a Python extension -- but every one of those reaches SQLite through a
/// cache-DB opener here or through the semantic-pack catalog, so those entry
/// points call this first and the `Once` keeps it to a single call.
///
/// [`MEMORY_STATISTICS_ENV`] is the way back on, one diagnostic run at a time.
/// Attributing the memory of a warm whole-workspace request means reading
/// `sqlite3_memory_used`, and that counter reads zero with the statistics off,
/// so a run that has to say how much of a request's heap is SQLite's sets the
/// variable and pays for it. It costs throughput under wide parallelism --
/// every allocation and free in every connection takes the one process-global
/// mutex again, which is the 37% of samples #2883 measured -- so it is never
/// the default and a measured run that leaves it set is not comparable with one
/// that does not.
pub fn disable_sqlite_memory_statistics() {
    static DISABLED: Once = Once::new();
    DISABLED.call_once(|| {
        if keeps_sqlite_memory_statistics(std::env::var_os(MEMORY_STATISTICS_ENV).as_deref()) {
            return;
        }
        // SAFETY: `sqlite3_config` is variadic, so it has no safe binding.
        // `SQLITE_CONFIG_MEMSTATUS` takes exactly one `c_int`. The call must not
        // race another SQLite call; `Once` serializes it, and every caller runs
        // it ahead of its own `Connection::open`.
        let code =
            unsafe { rusqlite::ffi::sqlite3_config(rusqlite::ffi::SQLITE_CONFIG_MEMSTATUS, 0) };
        if code != rusqlite::ffi::SQLITE_OK {
            // `SQLITE_MISUSE` is the only code this call returns, and it means
            // some other code in this process opened a raw SQLite connection
            // first, so the library is already initialized. Test binaries do
            // that; a Bifrost process does not. Leaving the statistics on costs
            // throughput, never correctness, so report it and open the store.
            eprintln!(
                "Bifrost kept SQLite memory statistics on: \
                 sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0) returned {code}"
            );
        }
    });
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
         2. For a durable machine-local cache, set BIFROST_CACHE_ROOT=<writable local root>. \
         Bifrost derives one repository-specific child and keeps linked worktrees sharing it.\n\
         3. If this run is deliberately transient, point BIFROST_CACHE_DIR at a throwaway \
         directory (`mktemp -d`) and delete it afterwards; nothing outlives the run.\n\
         4. Last resort: set BIFROST_CACHE_DIR=<writable dir> to relocate the cache. WARNING: \
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
        let _scope = crate::profiling::scope("cache_db.prepare_path");
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
    // #2771 is a mandatory cold start across FIRST_NATIVE_CACHE_VERSION.
    // Import selection and staging both reject older schemas before copying;
    // migrate() also replaces one found under this build's active filename.
    // Preserve this boundary when merging: historical bridges are test-only.
    // An older store is optional input. When it cannot be carried forward the
    // operator needs to know -- a cold start on an indexed corpus is hours of
    // re-embedding -- but a neighbouring file this build cannot read must not
    // be what stops the workspace from opening at all.
    let import_result = {
        let _scope = crate::profiling::scope("cache_db.import_older_store");
        import_newest_older_store(&db_path)
    };
    if let Err(error) = import_result {
        eprintln!("Bifrost cache upgrade skipped, starting a fresh store: {error}");
    }
    let mut conn = {
        let _scope = crate::profiling::scope("cache_db.sqlite_open");
        open_store_connection(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            ConnectionRole::Writer,
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
    };
    {
        let _scope = crate::profiling::scope("cache_db.configure_writer");
        install_busy_timeout(&conn)?;
        configure_connection_after_busy_timeout(&mut conn)?;
    }
    let initialized_before_open = {
        let _scope = crate::profiling::scope("cache_db.check_initialized");
        unified_cache_initialized(&conn)?
    };
    {
        let _scope = crate::profiling::scope("cache_db.migrate");
        migrate(&mut conn)?;
    }
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

/// Refuse SQLite WAL placement on a network filesystem before a persisted
/// workspace spends time discovering or parsing source files.
pub fn validate_writable_cache_filesystem(db_path: &Path) -> Result<()> {
    let allow_unsafe = std::env::var_os(ALLOW_NETWORK_CACHE_ENV)
        .is_some_and(|value| value == std::ffi::OsStr::new("1"));
    validate_network_cache_policy(db_path, network_filesystem_kind(db_path)?, allow_unsafe)
}

fn validate_network_cache_policy(
    db_path: &Path,
    filesystem_kind: Option<&str>,
    allow_unsafe: bool,
) -> Result<()> {
    let Some(filesystem_kind) = filesystem_kind else {
        return Ok(());
    };
    if allow_unsafe {
        return Ok(());
    }
    Err(format!(
        "refusing to place Bifrost SQLite WAL cache {} on {filesystem_kind}; SQLite WAL requires local filesystem locking and shared-memory semantics. Set {}=<local filesystem root> so each primary repository receives a machine-local cache. Set {ALLOW_NETWORK_CACHE_ENV}=1 only to accept the unsafe network-filesystem placement explicitly",
        db_path.display(),
        crate::gitblob::CACHE_ROOT_ENV,
    ))
}

#[cfg(target_os = "linux")]
fn network_filesystem_kind(path: &Path) -> Result<Option<&'static str>> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt as _;

    let existing = path
        .ancestors()
        .find(|candidate| candidate.is_dir())
        .ok_or_else(|| {
            format!(
                "cache DB path has no existing ancestor for filesystem inspection: {}",
                path.display()
            )
        })?;
    let encoded = CString::new(existing.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "cache DB path contains a NUL byte and cannot be inspected: {}",
            existing.display()
        )
    })?;
    let mut stats = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `encoded` is a live NUL-terminated path and `stats` points to
    // writable storage for one `statfs` result. A successful call initializes
    // the result before `assume_init`.
    let status = unsafe { libc::statfs(encoded.as_ptr(), stats.as_mut_ptr()) };
    if status != 0 {
        return Err(format!(
            "cache DB filesystem inspection failed for {}: {}",
            existing.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `statfs` returned success and initialized the output structure.
    let filesystem_type = unsafe { stats.assume_init() }.f_type as u64 & 0xffff_ffff;
    Ok(match filesystem_type {
        0x6969 => Some("NFS"),
        0xff53_4d42 => Some("CIFS/SMB"),
        _ => None,
    })
}

#[cfg(not(target_os = "linux"))]
fn network_filesystem_kind(_path: &Path) -> Result<Option<&'static str>> {
    Ok(None)
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
    disable_sqlite_memory_statistics();
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = open_store_connection(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::Reader,
    )
    .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_readonly_connection(&conn)?;
    Ok(conn)
}

/// SQLite's multi-thread mode, for a connection with exactly one owner at a
/// time.
///
/// The bundled SQLite is built `SQLITE_THREADSAFE=1` (serialized), so by default
/// every API call on a connection -- `sqlite3_step`, each `sqlite3_column_*`,
/// the finalize -- enters and leaves that connection's own mutex. That mutex
/// exists to let two threads share one connection, which Bifrost never does:
/// the analyzer store's reader pool moves a connection out of its idle vector to
/// hand it out and pushes it back on drop, so a checked-out reader has exactly
/// one owner for as long as it is out. Rust states the same invariant in the
/// type system, because `rusqlite::Connection` is `Send` and not `Sync`, which
/// is precisely SQLite's multi-thread contract. The pool has no way for two
/// guards to name one connection, so there is no concurrent-checkout state left
/// to assert against; ownership is the check.
///
/// This is a read-connection flag only. The writer stays serialized: it is
/// reached through a `Mutex` and a writer-actor thread, and proving the same
/// single-owner property for every path into it is a separate question (#2883).
const READER_THREADING: OpenFlags = OpenFlags::SQLITE_OPEN_NO_MUTEX;

/// Open an initialized cache with a read-only main database and a writable
/// temporary schema.
///
/// The SQLite read-only flag prevents persistent writes, while a writable TEMP
/// schema permits connection-local membership and FTS tables.
pub fn open_readonly_temp_connection(db_path: &Path) -> Result<Connection> {
    disable_sqlite_memory_statistics();
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = open_store_connection(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW | READER_THREADING,
        ConnectionRole::SessionReader,
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
/// prevents their page cache from displacing interactive analyzer queries.
pub fn open_streaming_readonly_connection(db_path: &Path) -> Result<Connection> {
    disable_sqlite_memory_statistics();
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = open_store_connection(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW | READER_THREADING,
        ConnectionRole::StreamingReader,
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
    // Keep interactive readers unmapped, with the page-cache budget above.
    // Mapping can bypass pcache1's global LRU mutex when SQLite is built with
    // SQLITE_ENABLE_MEMORY_MANAGEMENT (BrokkAi/bifrost#21). Workspace builds
    // instead undefine that option through LIBSQLITE3_FLAGS in .cargo/config.toml
    // so each page cache has a private reclamation group. This addresses the
    // shared mutex without adding mappings or changing mapped-I/O error and
    // file-truncation behavior. Downstream Rust builds do not inherit our Cargo
    // configuration and must apply the build flag themselves.
    //
    // Earlier mmap measurements predate the reader pool's concurrency cap and
    // do not establish the tradeoff for this configuration. Any reevaluation
    // should measure wall time and contention as well as memory: mappings of
    // the same file share physical pages, and file-backed RSS is reclaimable.
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
        let parent = prepare_cache_dir(parent)?;
        if let Some(file_name) = db_path.file_name() {
            return Ok(parent.join(file_name));
        }
    }
    Ok(db_path.to_path_buf())
}

/// Create and canonicalize one generated-cache directory, ensuring the
/// repository-default location cannot leak live cache files into Git walks.
pub fn prepare_cache_dir(cache_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))?;
    ensure_cache_dir_self_ignored(cache_dir)?;
    cache_dir
        .canonicalize()
        .map_err(|err| format!("cache DB I/O error: {err}"))
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
    let source_conn = open_store_connection(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::UpgradeSource,
    )
    .map_err(|err| {
        format!(
            "cache DB upgrade SQLite error reading {}: {err}",
            source.display()
        )
    })?;
    refuse_pre_native_import(&source_conn, source)?;
    let staged = tempfile::Builder::new()
        .prefix(".bifrost-cache-import")
        .tempfile_in(cache_dir)
        .map_err(|err| format!("failed to stage cache DB upgrade: {err}"))?
        // Release the handle. SQLite owns the path from here; the guard only
        // keeps the deletion-on-drop that makes a failed upgrade leave nothing.
        .into_temp_path();
    {
        source_conn
            .backup(rusqlite::MAIN_DB, &staged, None)
            .map_err(|err| {
                format!(
                    "cache DB upgrade SQLite error copying {}: {err}",
                    source.display()
                )
            })?;
    }
    let mut conn = open_store_connection(
        &staged,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::UpgradeTarget,
    )
    .map_err(|err| format!("cache DB upgrade SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    refuse_pre_native_import(&conn, source)?;
    migrate(&mut conn)?;
    verify_upgraded_store(&conn, source)?;
    drop(conn);
    Ok(staged)
}

fn refuse_pre_native_import(conn: &Connection, source: &Path) -> Result<()> {
    let version = cache_migration_version(conn)?;
    if version < FIRST_NATIVE_CACHE_VERSION {
        return Err(format!(
            "cache DB {} has pre-native schema version {version}; #2771 requires a fresh \
             native cache (first version {FIRST_NATIVE_CACHE_VERSION}), never an import",
            source.display(),
        ));
    }
    Ok(())
}

/// The upgraded copy must be indistinguishable from a store this build wrote.
///
/// A migration that merely does not raise is not proof. Version numbers are
/// per-lineage counters (as the historical foreign-store fixtures show), so a store can
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
        if version < FIRST_NATIVE_CACHE_VERSION {
            eprintln!(
                "Bifrost cache reset: ignoring pre-native store {} (schema {version}); #2771 starts fresh at schema {FIRST_NATIVE_CACHE_VERSION}",
                entry.path().display()
            );
            continue;
        }
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
        if legacy_version < FIRST_NATIVE_CACHE_VERSION {
            eprintln!(
                "Bifrost cache reset: ignoring pre-native store {} (schema {legacy_version}); #2771 starts fresh at schema {FIRST_NATIVE_CACHE_VERSION}",
                legacy.display()
            );
        }
        if (FIRST_NATIVE_CACHE_VERSION..=CURRENT_MIGRATION_VERSION).contains(&legacy_version)
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
    let conn = open_store_connection(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::VersionProbe,
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
    let writer_page_cache_kib = match std::env::var(WRITER_PAGE_CACHE_ENV) {
        Err(std::env::VarError::NotPresent) => WRITER_PAGE_CACHE_KIB,
        value => {
            let raw = value.map_err(|error| format!("{WRITER_PAGE_CACHE_ENV}: {error}"))?;
            let kib = raw.parse::<i32>().ok().filter(|kib| *kib > 0).ok_or_else(|| {
                format!(
                    "{WRITER_PAGE_CACHE_ENV} must be a positive integer in KiB (at most {}), got {raw:?}",
                    i32::MAX
                )
            })?;
            -i64::from(kib)
        }
    };
    if conn.path().is_some_and(|path| !path.is_empty()) {
        // Page size is an optional performance tuning choice. Initialize it
        // before the first schema write, but do not rebuild an existing store
        // just to change its page size; VACUUM would block the synchronous open.
        if let Err(error) =
            retry_initialization_phase("page-size initialization", || ensure_cache_page_size(conn))
        {
            eprintln!("Bifrost cache page-size initialization skipped: {error}");
        }
        retry_initialization_phase("auto-vacuum initialization", || {
            ensure_incremental_auto_vacuum(conn)
        })?;
        retry_initialization_phase("journal-mode initialization", || {
            ensure_wal_journal_mode(conn)
        })?;
    }
    // Overwrite freed pages with zeros. This is not a privacy setting here; it
    // is what keeps a WAL checkpoint from failing with SQLITE_CORRUPT after a
    // transaction leaves a non-empty freelist under `auto_vacuum=INCREMENTAL`
    // -- see `drain_free_pages` for the mechanism and
    // `.agents/docs/store-vacuum-and-secure-delete-decision-2026-09.md` for the
    // measurement that chose it (issue #2789).
    //
    // Spell the value, never number it. `PRAGMA secure_delete` parses its
    // argument as a boolean unless the argument is the literal word FAST, so
    // `secure_delete = 2` does not select FAST -- it sets full secure-delete
    // and reads back as 1.
    //
    // FAST would be the wrong choice anyway. It sets only `BTS_OVERWRITE`,
    // which clears deleted content inside pages that are being written and
    // leaves freelist leaf pages out of the WAL, so it costs 30 percent more
    // write bytes on a collection and still reproduces the checkpoint failure
    // at both page sizes.
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
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
    conn.pragma_update(None, "cache_size", writer_page_cache_kib)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "wal_autocheckpoint", 2000)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "journal_size_limit", WAL_JOURNAL_SIZE_LIMIT_BYTES)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

/// A closing writer can leave committed WAL frames pinned by another reader.
#[derive(Debug, PartialEq, Eq)]
pub enum CloseCheckpoint {
    Complete,
    Deferred {
        log_frames: i64,
        checkpointed_frames: i64,
    },
}

/// Request WAL truncation at the owning writer's shutdown boundary.
/// Concurrent readers can retain their snapshots after this writer closes;
/// report that ordinary contention separately from a SQLite operation failure.
pub fn checkpoint_wal_for_close(conn: &Connection) -> Result<CloseCheckpoint> {
    let busy_timeout_millis: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|err| format!("cache DB close checkpoint SQLite error: {err}"))?;
    conn.busy_timeout(Duration::ZERO)
        .map_err(|err| format!("cache DB close checkpoint SQLite error: {err}"))?;
    let checkpoint = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|err| format!("cache DB close checkpoint SQLite error: {err}"));
    debug_assert!(busy_timeout_millis >= 0);
    conn.busy_timeout(Duration::from_millis(
        u64::try_from(busy_timeout_millis).expect("SQLite busy_timeout is nonnegative"),
    ))
    .map_err(|err| format!("cache DB close checkpoint SQLite error: {err}"))?;
    let (busy, log_frames, checkpointed_frames) = checkpoint?;
    if busy == 0 {
        Ok(CloseCheckpoint::Complete)
    } else {
        Ok(CloseCheckpoint::Deferred {
            log_frames,
            checkpointed_frames,
        })
    }
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

/// Initialize fresh store files with [`CACHE_PAGE_SIZE_BYTES`] pages.
///
/// Page size is a persistent property of the database file, fixed in its
/// header. Changing it for an existing store requires a full `VACUUM` rebuild,
/// which is optional performance tuning and must not block a synchronous cache
/// open. Existing stores therefore retain their page size and continue through
/// the normal WAL and schema initialization phases.
fn ensure_cache_page_size(conn: &Connection) -> std::result::Result<(), InitializationPhaseError> {
    let current: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if current == CACHE_PAGE_SIZE_BYTES {
        return Ok(());
    }

    let schema_is_empty: bool = conn.query_row(
        "SELECT NOT EXISTS(
           SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?;
    if !schema_is_empty {
        return Ok(());
    }

    conn.pragma_update(None, "page_size", CACHE_PAGE_SIZE_BYTES)?;
    Ok(())
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
    let user_version = cache_migration_version(conn)?;
    if user_version == CURRENT_MIGRATION_VERSION && current_schema_shape_is_valid(conn)? {
        return Ok(());
    }

    if matches!(
        migrate_locked(conn, false)?,
        LockedMigrationOutcome::Complete
    ) {
        return drain_free_pages(conn);
    }

    // SQLite cannot change foreign-key enforcement within a transaction. The
    // first locked pass only detects a schema that needs replacement. Toggle
    // enforcement outside the transaction, then recheck while holding the
    // write lock before rebuilding it.
    conn.pragma_update(None, "foreign_keys", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let migration = match migrate_locked(conn, true) {
        Ok(LockedMigrationOutcome::Complete) => drain_free_pages(conn),
        Ok(LockedMigrationOutcome::RebuildRequired) => {
            Err("cache DB schema rebuild was not applied".to_string())
        }
        Err(error) => Err(error),
    };
    let restore = conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"));
    migration.and(restore)
}

/// Return every page on the freelist to the filesystem.
///
/// `PRAGMA incremental_vacuum` is a loop in the VDBE that emits one result row
/// per page it moves, so a caller that steps the statement once -- which is
/// what `Connection::pragma_update` and `execute_batch` do -- frees exactly one
/// page and leaves the rest of the freelist where it was. Draining the rows is
/// what runs the loop to completion. Every caller that has just deleted rows
/// must come through here; a bare pragma call silently reclaims one page.
///
/// The outer loop is a safety net for a build where one pass cannot empty the
/// list: it stops as soon as the freelist is empty or stops shrinking.
pub fn drain_free_pages(conn: &Connection) -> Result<()> {
    let mut previous = i64::MAX;
    loop {
        let free: i64 = conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        if free == 0 || free >= previous {
            return Ok(());
        }
        previous = free;
        let mut statement = conn
            .prepare("PRAGMA incremental_vacuum")
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        let mut pages = statement
            .query([])
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        while pages
            .next()
            .map_err(|err| format!("cache DB SQLite error: {err}"))?
            .is_some()
        {}
    }
}

enum LockedMigrationOutcome {
    Complete,
    RebuildRequired,
}

fn migrate_locked(
    conn: &mut Connection,
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
    if user_version > CURRENT_MIGRATION_VERSION {
        return Err(format!(
            "cache DB migration error: DatabaseTooFarAhead: user_version {user_version} exceeds {CURRENT_MIGRATION_VERSION} in {}. \
             Each schema version has its own store file, so this file's contents contradict its name; \
             moving it aside is safe and this build will import the newest compatible older store or \
             start a fresh one.",
            tx.path().unwrap_or("<in-memory>"),
        ));
    }

    let schema_objects = user_schema_objects(&tx)?;
    let below_floor = user_version < BASELINE_MIGRATION_VERSION
        && (user_version != 0 || !schema_objects.is_empty());
    let current_schema_invalid =
        user_version == CURRENT_MIGRATION_VERSION && !current_schema_shape_is_valid(&tx)?;
    if below_floor || current_schema_invalid {
        if !rebuild_invalid_schema {
            return Ok(LockedMigrationOutcome::RebuildRequired);
        }
        recreate_schema(&tx)?;
        user_version = 0;
    }

    if user_version == 0 {
        debug_assert!(user_schema_objects(&tx)?.is_empty());
        tx.execute_batch(BASELINE_SCHEMA_SQL)
            .map_err(|err| format!("cache DB baseline creation error: {err}"))?;
        tx.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
            .map_err(|err| format!("cache DB baseline version error: {err}"))?;
        start_collection_cadence(&tx)?;
        user_version = BASELINE_MIGRATION_VERSION;
    }

    for migration in POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version > user_version)
    {
        let version = migration.version;
        {
            let _scope = crate::profiling::scope_with(|| format!("cache_db.migration.{version}"));
            tx.execute_batch(migration.sql).map_err(|err| {
                format!("cache DB migration error applying version {version}: {err}")
            })?;
        }
        tx.pragma_update(None, "user_version", version)
            .map_err(|err| format!("cache DB migration error setting version {version}: {err}"))?;
    }

    validate_foreign_keys(&tx)?;
    if !current_schema_shape_is_valid(&tx)? {
        return Err("cache DB migration produced an unexpected schema".to_string());
    }
    tx.commit()
        .map_err(|err| format!("cache DB migration commit error: {err}"))?;
    Ok(LockedMigrationOutcome::Complete)
}

/// Start a new store's collection cadence at its creation time.
///
/// Collection becomes due when the store has grown and `GC_MIN_INTERVAL_SECS`
/// has passed since `last_gc_at` (`cache_gc::gc_due_tx`). The schema's own
/// `cache_state` row is written with `last_gc_at = 0`, which reads as the
/// epoch: permanently overdue. Every brand-new store therefore ran a full
/// sweep the moment its first build persisted a blob, over a store whose whole
/// content that build had just written and whose `blobs_at_last_gc` was zero
/// (issue #3170). That sweep held the analyzer-cache build lock, and the first
/// diff-derived MCP request behind it was reported as budget exhaustion.
///
/// A store created now is in the same position as one just collected -- there
/// is nothing in it to collect -- so its cadence starts here. This is not a
/// special case for `last_gc_at == 0`: a store that has genuinely never been
/// collected still becomes due on the ordinary time cadence, and an older
/// store migrated up to this schema keeps the value it recorded.
fn start_collection_cadence(tx: &Transaction<'_>) -> Result<()> {
    let updated = tx
        .execute(
            "UPDATE cache_state SET last_gc_at = ?1 WHERE id = 1",
            [now_unix_seconds()],
        )
        .map_err(|err| format!("cache DB collection cadence error: {err}"))?;
    assert_eq!(
        updated, 1,
        "a created store has exactly one cache_state row to start the collection cadence on"
    );
    Ok(())
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
    delete_legacy_cache_if_idle(&parent.join(LEGACY_ANALYZER_DB_FILE_NAME));
}

fn delete_legacy_cache_if_idle(legacy_path: &Path) {
    if let Err(error) = delete_store_if_idle(legacy_path) {
        eprintln!("Bifrost legacy cache cleanup skipped: {error}");
    }
}

/// Delete a store only while holding both its analyzer-build lock and an
/// exclusive SQLite claim. A busy lock leaves every file in place for a later
/// sweep; obsolete cache data must never interrupt a current-store open.
fn delete_store_if_idle(store: &Path) -> Result<bool> {
    if !store.exists() {
        return Ok(false);
    }
    // SQLITE_OPEN_NOFOLLOW refuses a symbolic link in any component of the
    // path, not only in the file name. Callers may name the cache directory
    // through one (macOS temp directories live under /var -> /private/var,
    // #3797), so resolve the directory first; the store file itself must
    // still not be a link.
    let store = &canonicalize_cache_db_parent(store)?;
    let lock_path = store_file_with_suffix(store, INITIAL_BUILD_LOCK_SUFFIX);
    let build_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| format!("cache DB I/O error opening {}: {err}", lock_path.display()))?;
    match build_lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(format!(
                "cache DB I/O error locking {}: {error}",
                lock_path.display()
            ));
        }
    }

    let mut connection = open_store_connection(
        store,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::Cleanup,
    )
    .map_err(|error| format!("cache DB cleanup SQLite error: {error}"))?;
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|error| format!("cache DB cleanup SQLite error: {error}"))?;
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(|error| format!("cache DB cleanup SQLite error: {error}"))?;
    let checkpoint_busy = match connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(busy) => busy,
        Err(error) if sqlite_is_busy_or_locked(&error) => return Ok(false),
        Err(error) => return Err(format!("cache DB cleanup SQLite error: {error}")),
    };
    if checkpoint_busy != 0 {
        return Ok(false);
    }
    let exclusive = match connection.transaction_with_behavior(TransactionBehavior::Exclusive) {
        Ok(exclusive) => exclusive,
        Err(error) if sqlite_is_busy_or_locked(&error) => return Ok(false),
        Err(error) => return Err(format!("cache DB cleanup SQLite error: {error}")),
    };

    #[cfg(windows)]
    let delete_claim = {
        // SQLite's Windows handles do not share DELETE access. Close our
        // verified-idle connection, then atomically claim DELETE access while
        // denying new readers and writers. A racing SQLite opener wins the
        // share check and leaves the complete store for a later sweep.
        drop(exclusive);
        drop(connection);
        match claim_windows_store_for_delete(store) {
            Ok(claim) => claim,
            Err(error) if windows_store_is_busy(&error) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(format!(
                    "cache DB I/O error claiming {} for deletion: {error}",
                    store.display()
                ));
            }
        }
    };

    // On Unix, keep the SQLite claim live through unlink. On Windows, the
    // delete claim denies new reads and writes while permitting deletion.
    // Delete the database last so a sidecar error leaves authoritative data.
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let path = store_file_with_suffix(store, suffix);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cache DB I/O error removing {}: {error}",
                    path.display()
                ));
            }
        }
    }
    match std::fs::remove_file(&lock_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cache DB I/O error removing {}: {error}",
                lock_path.display()
            ));
        }
    }
    #[cfg(windows)]
    drop(delete_claim);
    #[cfg(not(windows))]
    drop(exclusive);
    #[cfg(not(windows))]
    drop(connection);
    build_lock.unlock().map_err(|error| {
        format!(
            "cache DB I/O error unlocking {}: {error}",
            lock_path.display()
        )
    })?;
    Ok(true)
}

#[cfg(windows)]
fn claim_windows_store_for_delete(store: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    std::fs::OpenOptions::new()
        .access_mode(DELETE_ACCESS)
        .share_mode(FILE_SHARE_DELETE)
        .open(store)
}

#[cfg(windows)]
fn windows_store_is_busy(error: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    matches!(
        error.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

fn sqlite_is_busy_or_locked(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
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

fn user_schema_objects(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND type IN ('view', 'trigger', 'table')
             ORDER BY CASE type
                 WHEN 'trigger' THEN 0
                 WHEN 'view' THEN 1
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

fn cache_migration_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn schema_object_definitions_sha256(conn: &Connection) -> Result<[u8; 32]> {
    let definitions = schema_object_definitions(conn)?;
    let mut hasher = Sha256::new();
    for (object_type, name, sql) in definitions {
        for field in [object_type, name, sql] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
    }
    Ok(hasher.finalize().into())
}

fn current_schema_shape_is_valid(conn: &Connection) -> Result<bool> {
    if schema_object_definitions_sha256(conn)? != CURRENT_SCHEMA_OBJECTS_SHA256 {
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

fn quick_check_is_ok(conn: &Connection) -> Result<bool> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(result == "ok")
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
    // The EXPLAIN QUERY PLAN pins below run their assertions once against a
    // database with no planner statistics and once with the statistics
    // captured from real corpus stores, because production carries the latter
    // (issue #3016).
    use crate::cache_gc::PlannerStatisticsState;

    #[path = "cpp_class_templates.rs"]
    mod cpp_class_templates;
    #[path = "resolution_schema.rs"]
    mod resolution_schema;
    #[path = "rust_crate_rows.rs"]
    mod rust_crate_rows;
    #[path = "rust_item_macros.rs"]
    mod rust_item_macros;

    #[path = "rust_macro_contexts.rs"]
    mod rust_macro_contexts;
    #[path = "rust_type_forms.rs"]
    mod rust_type_forms;
    #[path = "source_import_path_availability.rs"]
    mod source_import_path_availability;

    /// The memory-statistics opt-in is exactly `1`.
    ///
    /// The decision is tested and not the effect: `sqlite3_config` is legal
    /// only while SQLite is uninitialized, the test binary has already opened
    /// connections by the time any test runs, and `Once` admits one call per
    /// process in any case. Which value turns the statistics on is the whole of
    /// what this function decides.
    #[test]
    fn sqlite_memory_statistics_stay_on_only_for_the_exact_opt_in() {
        assert!(keeps_sqlite_memory_statistics(Some(std::ffi::OsStr::new(
            "1"
        ))));
        assert!(!keeps_sqlite_memory_statistics(None));
        for other in ["", "0", "true", "yes", "11", " 1"] {
            assert!(
                !keeps_sqlite_memory_statistics(Some(std::ffi::OsStr::new(other))),
                "{MEMORY_STATISTICS_ENV}={other:?} must leave the default"
            );
        }
    }

    /// A database with no Bifrost schema in it, in the store's own shape:
    /// incremental auto-vacuum, WAL, and one transaction that frees pages.
    fn synthetic_store_with_free_pages(path: &Path, page_size: u32) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.pragma_update(None, "page_size", page_size).unwrap();
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
            .unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        // The page size and auto-vacuum mode only take effect once the file has
        // a header to hold them.
        conn.execute_batch("VACUUM;").unwrap();
        let filler = "x".repeat(2000);
        let mut sql = String::from("BEGIN;");
        for table in 0..40 {
            sql.push_str(&format!(
                "CREATE TABLE t{table}(a TEXT); INSERT INTO t{table}(a) VALUES('{filler}');"
            ));
        }
        for table in 0..40 {
            sql.push_str(&format!("DROP TABLE t{table};"));
        }
        sql.push_str("COMMIT;");
        conn.execute_batch(&sql).unwrap();
        let free: i64 = conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .unwrap();
        assert!(free > 0, "the workload must leave pages on the freelist");
        conn
    }

    /// The tripwire for the upstream defect the store used to be exposed to. A
    /// bundled SQLite built without `SQLITE_SECURE_DELETE` cannot checkpoint a
    /// WAL database that has a non-empty freelist under incremental
    /// auto-vacuum, on every release from 3.45.0 through 3.53.4, and this
    /// connection is raw so it still meets that condition.
    ///
    /// If the first half of this test fails, the upstream condition is gone and
    /// the `secure_delete` pragma in `configure_connection_after_busy_timeout`
    /// is no longer load-bearing -- it can go back to being a free choice, and
    /// its own test with it. If the second half fails, draining no longer
    /// clears the state.
    ///
    /// `store_connection_configuration_checkpoints_a_store_with_free_pages` is
    /// the other half: it asserts that the store's own connections do not meet
    /// the condition at all.
    #[test]
    fn free_pages_under_incremental_auto_vacuum_still_break_wal_checkpoints() {
        let temp = tempfile::tempdir().unwrap();
        for (index, page_size) in [4096u32, 32768].into_iter().enumerate() {
            let undrained = temp.path().join(format!("undrained{index}.db"));
            let conn = synthetic_store_with_free_pages(&undrained, page_size);
            let blocked = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            });
            let error = blocked.expect_err(&format!(
                "SQLite {} checkpointed a {page_size}-byte-page store with free pages: \
                 the defect drain_free_pages works around is fixed, so delete it",
                rusqlite::version()
            ));
            assert!(
                matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseCorrupt)
                ),
                "unexpected checkpoint failure: {error:?}"
            );

            let drained = temp.path().join(format!("drained{index}.db"));
            let conn = synthetic_store_with_free_pages(&drained, page_size);
            drain_free_pages(&conn).unwrap();
            let busy = conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(busy, 0, "the drained store must checkpoint");
        }
    }

    /// The store's own write-connection configuration must not meet the
    /// condition the tripwire above pins: a transaction that leaves a
    /// non-empty freelist must still checkpoint, undrained (issue #2789).
    #[test]
    fn store_connection_configuration_checkpoints_a_store_with_free_pages() {
        let temp = tempfile::tempdir().unwrap();
        for (index, page_size) in [4096u32, 32768].into_iter().enumerate() {
            let path = temp.path().join(format!("configured{index}.db"));
            let mut conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "page_size", page_size).unwrap();
            configure_connection(&mut conn).unwrap();
            let secure_delete: i64 = conn
                .query_row("PRAGMA secure_delete", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                secure_delete, 1,
                "the store's connections must run full secure-delete, not OFF (0) or FAST (2)"
            );
            let auto_vacuum: i64 = conn
                .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
                .unwrap();
            assert_eq!(auto_vacuum, 2, "the workload needs incremental auto-vacuum");

            let filler = "x".repeat(2000);
            let mut sql = String::from("BEGIN;");
            for table in 0..40 {
                sql.push_str(&format!(
                    "CREATE TABLE t{table}(a TEXT); INSERT INTO t{table}(a) VALUES('{filler}');"
                ));
            }
            for table in 0..40 {
                sql.push_str(&format!("DROP TABLE t{table};"));
            }
            sql.push_str("COMMIT;");
            conn.execute_batch(&sql).unwrap();
            let free: i64 = conn
                .query_row("PRAGMA freelist_count", [], |row| row.get(0))
                .unwrap();
            assert!(free > 0, "the workload must leave pages on the freelist");

            let busy = conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or_else(|error| {
                    panic!(
                        "a {page_size}-byte-page store configured the production way must \
                         checkpoint with {free} free pages, on SQLite {}: {error}",
                        rusqlite::version()
                    )
                });
            assert_eq!(busy, 0, "the checkpoint must complete");
        }
    }

    #[test]
    fn writer_policy_limits_and_truncates_the_wal() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(cache_db_file_name());
        let conn = open_unified_connection(&path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA journal_size_limit", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            WAL_JOURNAL_SIZE_LIMIT_BYTES
        );
        // A write burst rather than one row: the close boundary has to bound
        // the WAL a real build leaves behind, not only a single frame.
        conn.execute_batch("BEGIN").unwrap();
        {
            let mut insert = conn
                .prepare(
                    "INSERT INTO blobs(blob_oid, lang, generation)
                     VALUES(printf('%040x', ?1), 'rust', 0)",
                )
                .unwrap();
            for row in 0..5_000 {
                insert.execute([row]).unwrap();
            }
        }
        conn.execute_batch("COMMIT").unwrap();
        let wal = store_file_with_suffix(&path, "-wal");
        let burst_bytes = std::fs::metadata(&wal).unwrap().len();
        assert!(
            burst_bytes > 64 * 1024,
            "the burst must leave a multi-page WAL behind: {burst_bytes} bytes"
        );

        checkpoint_wal_for_close(&conn).unwrap();

        let closed_bytes = std::fs::metadata(wal).unwrap().len();
        assert!(
            closed_bytes <= u64::try_from(WAL_JOURNAL_SIZE_LIMIT_BYTES).unwrap(),
            "the close checkpoint must bound the WAL: {closed_bytes} bytes"
        );
        assert_eq!(closed_bytes, 0, "a TRUNCATE checkpoint empties the WAL");
    }

    #[test]
    fn close_checkpoint_reports_an_active_reader_and_succeeds_after_release() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(cache_db_file_name());
        let writer = open_unified_connection(&path).unwrap();
        writer
            .execute(
                "INSERT INTO blobs(blob_oid, lang, generation)
                 VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rust', 0)",
                [],
            )
            .unwrap();
        checkpoint_wal_for_close(&writer).unwrap();

        let reader = open_readonly_connection(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        assert_eq!(
            reader
                .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        writer
            .execute(
                "INSERT INTO blobs(blob_oid, lang, generation)
                 VALUES('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'rust', 0)",
                [],
            )
            .unwrap();

        let checkpoint = checkpoint_wal_for_close(&writer).unwrap();
        assert!(
            matches!(checkpoint, CloseCheckpoint::Deferred { .. }),
            "{checkpoint:?}"
        );
        assert_eq!(
            reader
                .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1,
            "deferring truncation preserves the active snapshot"
        );
        reader.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            checkpoint_wal_for_close(&writer).unwrap(),
            CloseCheckpoint::Complete
        );
    }

    #[test]
    fn close_checkpoint_preserves_sqlite_errors_and_restores_busy_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(cache_db_file_name());
        let writer = open_unified_connection(&path).unwrap();
        writer.busy_timeout(Duration::from_millis(123)).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let error = checkpoint_wal_for_close(&writer).unwrap_err();
        assert!(error.contains("SQLite error"), "{error}");
        assert_eq!(
            writer
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            123
        );
        writer.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            checkpoint_wal_for_close(&writer).unwrap(),
            CloseCheckpoint::Complete
        );
    }

    #[test]
    fn opening_current_store_removes_idle_subfloor_stores_and_build_locks() {
        let temp = tempfile::tempdir().unwrap();
        for version in [62, 116] {
            let store = temp.path().join(cache_db_file_name_for_version(version));
            let connection = Connection::open(&store).unwrap();
            connection
                .execute_batch("CREATE TABLE obsolete(value TEXT) STRICT;")
                .unwrap();
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            drop(connection);
            std::fs::write(
                store_file_with_suffix(&store, INITIAL_BUILD_LOCK_SUFFIX),
                b"",
            )
            .unwrap();
        }

        let current = temp.path().join(cache_db_file_name());
        let connection = open_unified_connection(&current).unwrap();
        assert!(current_schema_is_valid(&connection).unwrap());
        for version in [62, 116] {
            let store = temp.path().join(cache_db_file_name_for_version(version));
            assert!(!store.exists(), "obsolete schema {version} survived open");
            assert!(!store_file_with_suffix(&store, INITIAL_BUILD_LOCK_SUFFIX).exists());
        }
    }

    #[test]
    fn opening_current_store_preserves_a_locked_subfloor_store() {
        let temp = tempfile::tempdir().unwrap();
        let obsolete = temp.path().join(cache_db_file_name_for_version(116));
        Connection::open(&obsolete)
            .unwrap()
            .execute_batch("CREATE TABLE obsolete(value TEXT) STRICT;")
            .unwrap();
        let lock_path = store_file_with_suffix(&obsolete, INITIAL_BUILD_LOCK_SUFFIX);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        lock.lock().unwrap();

        let current = temp.path().join(cache_db_file_name());
        let connection = open_unified_connection(&current).unwrap();

        assert!(current_schema_is_valid(&connection).unwrap());
        assert!(obsolete.exists());
        assert!(lock_path.exists());
        lock.unlock().unwrap();
    }

    fn open_in_memory_cache() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn
    }

    fn insert_signature_metadata_pair_fixture(
        conn: &Connection,
        seed: &str,
        is_complete: i64,
    ) -> i64 {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES(?1, 'java', 0)",
            [seeded_oid(seed)],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             ) VALUES(?1, 'java', 0, '', 1, 0, 1, 1, 0, 0, 0, 0, ?2)",
            rusqlite::params![blob_id, is_complete],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'java', 1, 0, 'callable', 'callable', '', 0, 0, 1, 1)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO unit_signatures(
               blob_id, lang, unit_key, ordinal, text
             ) VALUES(?1, 'java', 1, 0, 'callable()')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata(
               blob_id, lang, unit_key, ordinal, label, parameters
             ) VALUES(?1, 'java', 1, 0, 'callable', '[]')",
            [blob_id],
        )
        .unwrap();
        blob_id
    }

    fn insert_nested_source_fixture(conn: &Connection, depth: i64) -> i64 {
        let blob_id = insert_visibility_blob_fixture(conn, &format!("nested-{depth}"), None, 1);
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, ?2 * 2, ?2, 0, 0, ?2, 0, 0, 2 + ?2, 0, 'building')",
            rusqlite::params![blob_id, depth],
        )
        .unwrap();
        // Occurrence `n` spans [n, depth * 2 - n); the arena is that list, in
        // id order.
        let arena = (0..depth)
            .map(|node_id| format!("[{node_id},{},1,1,0]", depth * 2 - node_id))
            .collect::<Vec<_>>()
            .join(",");
        conn.execute(
            "INSERT INTO source_occurrence_arenas(blob_id, spans) VALUES(?1, jsonb(?2))",
            rusqlite::params![blob_id, format!("[{arena}]")],
        )
        .unwrap();
        // kind_code 14 is NormalizedKind::Identifier. Each node's name span is
        // its own, and node n nests inside node n - 1.
        let nodes = (0..depth)
            .map(|node_id| {
                let parent = if node_id > 0 {
                    (node_id - 1).to_string()
                } else {
                    "null".to_owned()
                };
                format!(
                    "[14,null,null,{node_id},{end},{node_id},{end},{parent},{depth},null,null,null]",
                    end = depth * 2 - node_id
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        conn.execute(
            "INSERT INTO source_structural_facts(blob_id, nodes, roles, occurrence_roles)
             VALUES(?1, jsonb(?2), jsonb('[]'), jsonb('[]'))",
            rusqlite::params![blob_id, format!("[{nodes}]")],
        )
        .unwrap();
        blob_id
    }

    fn insert_visibility_blob_fixture(
        conn: &Connection,
        seed: &str,
        declaration_visibility_version: Option<i64>,
        is_complete: i64,
    ) -> i64 {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES(?1, 'java', 0)",
            [seeded_oid(seed)],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete,
               declaration_visibility_version
             ) VALUES(?1, 'java', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, ?2, ?3)",
            rusqlite::params![blob_id, is_complete, declaration_visibility_version],
        )
        .unwrap();
        blob_id
    }

    fn insert_empty_visibility_source(conn: &Connection, blob_id: i64) {
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 'building')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_occurrence_arenas(blob_id, spans) VALUES(?1, jsonb('[]'))",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibility_manifests(
               blob_id, facts_version, visibility_count,
               native_bridge_count, metadata_bridge_count
             ) VALUES(?1, 1, 0, 0, 0)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
    }

    #[test]
    fn canonical_signature_parameters_are_relational_complete_and_sealed() {
        let conn = open_in_memory_cache();
        let blob_id = insert_visibility_blob_fixture(&conn, "signature-parameters", None, 0);
        conn.execute(
            "INSERT INTO code_units(blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias, in_declarations, in_definition_lookup)
             VALUES(?1, 'java', 1, 0, 'Example', 'Example', '', 0, 0, 1, 1)",
            [blob_id],
        )
        .unwrap();
        let parameters = r#"[{"label":"value: T","name":"value","start_byte":3,"end_byte":11}]"#;
        conn.execute(
            "INSERT INTO unit_signature_metadata(blob_id, lang, unit_key, ordinal, label,
               parameters, class_like_kind) VALUES(?1, 'java', 1, 0, 'fn(value: T)', ?2, 'interface')",
            rusqlite::params![blob_id, parameters],
        ).unwrap();
        let stored: (String, i64, String) = conn
            .query_row(
                "SELECT metadata.parameters, metadata.parameter_count, parameter.name
             FROM unit_signature_metadata AS metadata JOIN unit_signature_parameters AS parameter
               ON parameter.blob_id = metadata.blob_id AND parameter.unit_key = metadata.unit_key
              AND parameter.metadata_ordinal = metadata.ordinal WHERE metadata.blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored, ("[]".to_string(), 1, "value".to_string()));
        let projected: (String, bool, bool) = conn
            .query_row(
                "SELECT parameters, class_like_is_interface, metadata_available
             FROM unit_signature_metadata_values WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(projected, (parameters.to_string(), true, true));
        conn.execute(
            "DELETE FROM unit_signature_parameters WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        assert!(!conn.query_row(
            "SELECT metadata_available FROM unit_signature_metadata_values WHERE blob_id = ?1",
            [blob_id], |row| row.get::<_, bool>(0),
        ).unwrap(), "missing parameter publication cannot look like an empty parameter list");
        conn.execute(
            "INSERT INTO unit_signature_parameters(blob_id, unit_key, metadata_ordinal, ordinal,
               label, name, start_byte, end_byte) VALUES(?1, 1, 0, 0, 'value: T', 'value', 3, 11)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE blob_meta SET is_complete = 1 WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE unit_signature_parameters SET name = 'other' WHERE blob_id = ?1",
                [blob_id]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "DELETE FROM unit_signature_parameters WHERE blob_id = ?1",
                [blob_id]
            )
            .is_err()
        );
        conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM unit_signature_parameters WHERE blob_id = ?1",
                [blob_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn schema64_visibility_readiness_distinguishes_legacy_missing_and_empty() {
        let conn = open_in_memory_cache();
        let legacy_blob = insert_visibility_blob_fixture(&conn, "visibility-legacy", None, 1);
        let missing_blob = insert_visibility_blob_fixture(&conn, "visibility-missing", Some(1), 1);
        let empty_blob = insert_visibility_blob_fixture(&conn, "visibility-empty", Some(1), 1);

        assert_eq!(
            conn.query_row(
                "SELECT available FROM source_declaration_visibility_readiness
                 WHERE blob_id = ?1",
                [legacy_blob],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT available FROM source_declaration_visibility_readiness
                 WHERE blob_id = ?1",
                [missing_blob],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM live_parsed_blobs WHERE blob_id = ?1",
                [missing_blob],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );

        insert_empty_visibility_source(&conn, empty_blob);
        assert_eq!(
            conn.query_row(
                "SELECT available FROM source_declaration_visibility_readiness
                 WHERE blob_id = ?1",
                [empty_blob],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "an explicitly published empty family is available"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM live_parsed_blobs WHERE blob_id = ?1",
                [empty_blob],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );

        assert!(
            conn.execute(
                "UPDATE blob_meta SET declaration_visibility_version = NULL
                 WHERE blob_id = ?1",
                [empty_blob],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE source_declaration_visibility_manifests
                    SET facts_version = 1
                  WHERE blob_id = ?1",
                [empty_blob],
            )
            .is_err()
        );

        conn.execute("DELETE FROM blobs WHERE id = ?1", [empty_blob])
            .unwrap();
        for table in [
            "source_declaration_visibility_manifests",
            "source_declaration_visibilities",
            "source_native_declaration_bridges",
            "source_declaration_metadata_bridges",
        ] {
            assert_eq!(
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                    [empty_blob],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                0,
                "whole-blob replacement must cascade {table}"
            );
        }
    }

    #[test]
    fn schema64_visibility_view_keeps_legacy_rows_and_canonical_rows_are_noop() {
        let conn = open_in_memory_cache();
        let legacy_blob = insert_visibility_blob_fixture(&conn, "visibility-view-legacy", None, 1);
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'schema64-test', ?2, 0, 2, 0, 'building')",
            rusqlite::params![legacy_blob, vec![0_u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_declaration_visibility_properties(
               blob_id, definition_semantic_key, visibility
             ) VALUES(?1, 0, 'private')",
            [legacy_blob],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT visibility FROM resolution_declaration_visibility_properties
                 WHERE blob_id = ?1 AND definition_semantic_key = 0",
                [legacy_blob],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "private"
        );
        assert_eq!(
            conn.query_row(
                "SELECT type FROM sqlite_master
                 WHERE name = 'resolution_declaration_visibility_properties'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "view"
        );
        assert_eq!(
            conn.query_row(
                "SELECT type FROM sqlite_master
                 WHERE name = 'legacy_resolution_declaration_visibility_properties'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "table"
        );

        let canonical_blob =
            insert_visibility_blob_fixture(&conn, "visibility-view-canonical", Some(1), 1);
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 1, 1, 1, 0, 0, 0, 0, 6, 6, 'building')",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_occurrence_arenas(blob_id, spans)
                 VALUES(?1, jsonb('[[0,1,1,1,0]]'))",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 0, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][2]'), json_extract(arena.spans, '$[0][3]'), NULL, NULL, NULL, NULL, json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibilities(blob_id, declaration_id, visibility)
             VALUES(?1, 0, 'public')",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_native_declaration_bridges(blob_id, source_site, declaration_id)
             VALUES(?1, 1, 0)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibility_manifests(
               blob_id, facts_version, visibility_count,
               native_bridge_count, metadata_bridge_count
             ) VALUES(?1, 1, 1, 1, 0)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, expected_declaration_visibility_property_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'schema64-test', ?2, 1, 1, 3, 0, 'building')",
            rusqlite::params![canonical_blob, vec![2_u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_semantic_sites(
               blob_id, source_site, namespace, semantic_role, semantic_key
             ) VALUES(?1, 1, 'value', 'definition', 0)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [canonical_blob],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT visibility FROM resolution_declaration_visibility_properties
                 WHERE blob_id = ?1 AND definition_semantic_key = 0",
                [canonical_blob],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "public"
        );
        conn.execute(
            "INSERT INTO resolution_declaration_visibility_properties(
               blob_id, definition_semantic_key, visibility
             ) VALUES(?1, 0, 'public')",
            [canonical_blob],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO resolution_declaration_visibility_properties(
                   blob_id, definition_semantic_key, visibility
                 ) VALUES(?1, 0, 'private')",
                [canonical_blob],
            )
            .is_err()
        );
    }

    #[test]
    fn schema64_metadata_view_reports_exact_source_visibility_or_unavailable() {
        let conn = open_in_memory_cache();
        let canonical_blob =
            insert_visibility_blob_fixture(&conn, "visibility-metadata", Some(1), 1);
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'java', 1, 0, 'callable', 'callable', '', 0, 0, 1, 1)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata(
               blob_id, lang, unit_key, ordinal, label,
               parameters, callable_declared_visibility
             ) VALUES(?1, 'java', 1, 0, 'callable', '[]', 'private')",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 1, 1, 1, 1, 0, 0, 0, 7, 6, 'building')",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_occurrence_arenas(blob_id, spans)
                 VALUES(?1, jsonb('[[0,1,1,1,0]]'))",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 0, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][2]'), json_extract(arena.spans, '$[0][3]'), NULL, NULL, NULL, NULL, json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibilities(blob_id, declaration_id, visibility)
             VALUES(?1, 0, 'public')",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_units(blob_id, declaration_id, unit_key)
             VALUES(?1, 0, 1)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_metadata_bridges(
               blob_id, declaration_id, unit_key, metadata_ordinal
             ) VALUES(?1, 0, 1, 0)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibility_manifests(
               blob_id, facts_version, visibility_count,
               native_bridge_count, metadata_bridge_count
             ) VALUES(?1, 1, 1, 0, 1)",
            [canonical_blob],
        )
        .unwrap();
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [canonical_blob],
        )
        .unwrap();

        let (visibility, available): (String, i64) = conn
            .query_row(
                "SELECT callable_declared_visibility, metadata_available
                 FROM unit_signature_metadata_values
                 WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
                [canonical_blob],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(visibility, "public");
        assert_eq!(available, 1);

        let incomplete_blob = insert_visibility_blob_fixture(&conn, "missing-metadata", Some(1), 1);
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'java', 1, 0, 'missing', 'missing', '', 0, 0, 1, 1)",
            [incomplete_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata(
               blob_id, lang, unit_key, ordinal, label,
               parameters, callable_declared_visibility
             ) VALUES(?1, 'java', 1, 0, 'missing', '[]', 'private')",
            [incomplete_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 'building')",
            [incomplete_blob],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO source_declaration_visibility_manifests(
                   blob_id, facts_version, visibility_count,
                   native_bridge_count, metadata_bridge_count
                 ) VALUES(?1, 1, 0, 0, 0)",
                [incomplete_blob],
            )
            .is_err(),
            "the family marker must reject an uncovered nonsynthetic metadata row"
        );
        let (visibility, available): (Option<String>, i64) = conn
            .query_row(
                "SELECT callable_declared_visibility, metadata_available
                 FROM unit_signature_metadata_values
                 WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
                [incomplete_blob],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(visibility, None);
        assert_eq!(available, 0);

        let synthetic_blob =
            insert_visibility_blob_fixture(&conn, "synthetic-metadata", Some(1), 1);
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'java', 1, 0, 'synthetic', 'synthetic', '', 1, 0, 1, 1)",
            [synthetic_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata(
               blob_id, lang, unit_key, ordinal, label,
               parameters, callable_declared_visibility
             ) VALUES(?1, 'java', 1, 0, 'synthetic', '[]', 'private')",
            [synthetic_blob],
        )
        .unwrap();
        insert_empty_visibility_source(&conn, synthetic_blob);
        let (visibility, available): (String, i64) = conn
            .query_row(
                "SELECT callable_declared_visibility, metadata_available
                 FROM unit_signature_metadata_values
                 WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
                [synthetic_blob],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(visibility, "private");
        assert_eq!(
            available, 1,
            "synthetic metadata has no source visibility requirement"
        );
    }

    #[test]
    fn schema64_native_bridges_require_definition_sites_at_native_seal() {
        let conn = open_in_memory_cache();
        let blob_id = insert_visibility_blob_fixture(&conn, "visibility-native-seal", Some(1), 1);
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 1, 1, 1, 0, 0, 0, 0, 6, 6, 'building')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_occurrence_arenas(blob_id, spans)
                 VALUES(?1, jsonb('[[0,1,1,1,0]]'))",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 0, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][2]'), json_extract(arena.spans, '$[0][3]'), NULL, NULL, NULL, NULL, json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibilities(blob_id, declaration_id, visibility)
             VALUES(?1, 0, 'public')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_native_declaration_bridges(blob_id, source_site, declaration_id)
             VALUES(?1, 9, 0)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_declaration_visibility_manifests(
               blob_id, facts_version, visibility_count,
               native_bridge_count, metadata_bridge_count
             ) VALUES(?1, 1, 1, 1, 0)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'schema64-test', ?2, 0, 1, 0, 'building')",
            rusqlite::params![blob_id, vec![5_u8; 32]],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE resolution_fragment_interiors SET publication_state = 'complete'
                 WHERE blob_id = ?1",
                [blob_id],
            )
            .is_err(),
            "native completion must reject a bridge whose source site is absent"
        );
    }

    #[test]
    fn java_type_constructor_shape_columns_reject_partial_or_invalid_values() {
        let conn = open_in_memory_cache();
        let blob_id = insert_signature_metadata_pair_fixture(&conn, "constructor-checks", 0);
        let update = "UPDATE unit_signature_metadata
            SET java_constructor_shape = ?2, java_constructor_arity_required = ?3,
                java_constructor_arity_total = ?4, java_constructor_arity_repeated = ?5
            WHERE blob_id = ?1";
        for (kind, required, total, repeated) in [
            (None, Some(0), Some(0), Some(0)),
            (Some(0), Some(0), Some(0), Some(0)),
            (Some(1), None, Some(0), None),
            (Some(2), None, None, None),
            (Some(2), Some(0), Some(0), None),
            (Some(2), Some(2), Some(1), Some(0)),
            (Some(2), Some(0), Some(1), Some(2)),
            (Some(2), Some(-1), Some(1), Some(1)),
            (Some(3), None, None, None),
        ] {
            assert!(
                conn.execute(
                    update,
                    rusqlite::params![blob_id, kind, required, total, repeated]
                )
                .is_err(),
                "invalid Java constructor tuple was accepted: {:?}",
                (kind, required, total, repeated)
            );
        }
        for (kind, required, total, repeated) in [
            (None, None, None, None),
            (Some(0), None, None, None),
            (Some(1), None, None, None),
            (Some(2), Some(1), Some(2), Some(1)),
        ] {
            conn.execute(
                update,
                rusqlite::params![blob_id, kind, required, total, repeated],
            )
            .unwrap();
        }
        assert!(
            conn.execute(
                "UPDATE code_units SET kind = 1 WHERE blob_id = ?1",
                [blob_id]
            )
            .is_err()
        );
        conn.execute(
            update,
            rusqlite::params![
                blob_id,
                Option::<i64>::None,
                Option::<i64>::None,
                Option::<i64>::None,
                Option::<i64>::None
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE code_units SET kind = 1 WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        assert!(
            conn.execute(
                update,
                rusqlite::params![
                    blob_id,
                    1,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<i64>::None
                ]
            )
            .is_err(),
            "constructor shape cannot be attached to a function"
        );
    }

    #[test]
    fn signature_metadata_pairs_require_exact_fks_and_cascade_as_one_family() {
        let conn = open_in_memory_cache();
        let blob_id = insert_signature_metadata_pair_fixture(&conn, "pair-laws", 0);

        conn.execute_batch("BEGIN").unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata_signatures(
               blob_id, unit_key, metadata_ordinal, signature_ordinal
             ) VALUES(?1, 1, 0, 9)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE blob_meta SET is_complete = 1 WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
             VALUES(?1, 6, 1)",
            [blob_id],
        )
        .unwrap();
        let invalid_signature_commit = conn.execute_batch("COMMIT");
        assert!(
            invalid_signature_commit.is_err(),
            "a nonexistent signature ordinal must fail at the deferred FK boundary"
        );
        conn.execute_batch("ROLLBACK").unwrap();

        let missing_marker_blob_id =
            insert_signature_metadata_pair_fixture(&conn, "pair-missing-marker", 0);
        conn.execute_batch("BEGIN").unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata_signatures(
               blob_id, unit_key, metadata_ordinal, signature_ordinal
             ) VALUES(?1, 1, 0, 0)",
            [missing_marker_blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE blob_meta SET is_complete = 1 WHERE blob_id = ?1",
            [missing_marker_blob_id],
        )
        .unwrap();
        let missing_marker_commit = conn.execute_batch("COMMIT");
        assert!(
            missing_marker_commit.is_err(),
            "a pair without the family marker must fail at its deferred FK boundary"
        );
        conn.execute_batch("ROLLBACK").unwrap();

        conn.execute_batch("BEGIN").unwrap();
        conn.execute(
            "INSERT INTO unit_signature_metadata_signatures(
               blob_id, unit_key, metadata_ordinal, signature_ordinal
             ) VALUES(?1, 1, 0, 0)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE blob_meta SET is_complete = 1 WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
             VALUES(?1, 6, 1)",
            [blob_id],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();

        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
                 VALUES(?1, 6, 1)",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE unit_signature_metadata_signatures
                    SET signature_ordinal = 0
                  WHERE blob_id = ?1 AND unit_key = 1 AND metadata_ordinal = 0",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "DELETE FROM unit_signature_metadata_signatures
                  WHERE blob_id = ?1 AND unit_key = 1 AND metadata_ordinal = 0",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE unit_signatures SET text = 'changed'
                  WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE unit_signature_metadata SET label = 'changed'
                  WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO unit_signature_metadata(
                   blob_id, lang, unit_key, ordinal, label, parameters
                 ) VALUES(?1, 'java', 1, 1, 'extra', '[]')",
                [blob_id],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE blob_meta SET signature_metadata_count = 2
                  WHERE blob_id = ?1",
                [blob_id],
            )
            .is_err()
        );

        conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
            .unwrap();
        for table in [
            "unit_signature_metadata_signatures",
            "unit_signature_metadata",
            "unit_signatures",
            "blob_optional_fact_manifest",
        ] {
            assert_eq!(
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                    [blob_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                0,
                "blob replacement must cascade {table}"
            );
        }
    }

    #[test]
    fn signature_metadata_pair_marker_is_insert_only_and_requires_complete_header() {
        let conn = open_in_memory_cache();

        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES(?1, 'java', 0)",
            [seeded_oid("pair-no-header")],
        )
        .unwrap();
        let no_header_blob_id = conn.last_insert_rowid();
        assert!(
            conn.execute(
                "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
                 VALUES(?1, 6, 1)",
                [no_header_blob_id],
            )
            .is_err()
        );

        let blob_id = insert_signature_metadata_pair_fixture(&conn, "pair-kind-update", 0);
        conn.execute(
            "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
             VALUES(?1, 5, 1)",
            [blob_id],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE blob_optional_fact_manifest
                    SET fact_kind = 6
                  WHERE blob_id = ?1 AND fact_kind = 5",
                [blob_id],
            )
            .is_err()
        );
    }

    #[test]
    fn current_schema_digest_matches_the_baseline_chain() {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS {
            conn.execute_batch(migration.sql).unwrap();
        }
        assert_eq!(
            schema_object_definitions_sha256(&conn).unwrap(),
            CURRENT_SCHEMA_OBJECTS_SHA256
        );
    }

    #[test]
    fn python_runtime_member_checks_reject_nullable_verified_mutations() {
        let (conn, acquisition_id, environment_id, artifact_id, _) =
            python_runtime_mutation_fixture();
        let digest = "a".repeat(64);
        let mismatch_digest = "b".repeat(64);

        // Nullable byte evidence remains valid for unresolved members.
        insert_python_runtime_member(
            &conn,
            (acquisition_id, environment_id, artifact_id),
            PythonRuntimeMemberInsert {
                status: "unresolved",
                installed_path: None,
                member_sha256: None,
                installed_sha256: None,
                installed_bytes_match: None,
            },
        )
        .unwrap();

        let invalid_members = [
            (
                "bytes_matched with a NULL match flag",
                "bytes_matched",
                Some("/site/module.py"),
                Some(digest.as_str()),
                Some(digest.as_str()),
                None,
            ),
            (
                "match flag 1 with a NULL installed digest",
                "unresolved",
                None,
                Some(digest.as_str()),
                None,
                Some(1),
            ),
            (
                "missing_installed with a NULL match flag",
                "missing_installed",
                None,
                Some(digest.as_str()),
                None,
                None,
            ),
            (
                "content_mismatch with a NULL match flag",
                "content_mismatch",
                Some("/site/module.py"),
                Some(digest.as_str()),
                Some(mismatch_digest.as_str()),
                None,
            ),
        ];

        for (description, status, installed_path, member_sha256, installed_sha256, matched) in
            invalid_members
        {
            let error = insert_python_runtime_member(
                &conn,
                (acquisition_id, environment_id, artifact_id),
                PythonRuntimeMemberInsert {
                    status,
                    installed_path,
                    member_sha256,
                    installed_sha256,
                    installed_bytes_match: matched,
                },
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("CHECK constraint failed"),
                "{description} must be rejected by a CHECK constraint, got {error}"
            );
        }
    }

    #[test]
    fn python_runtime_provider_rejects_member_from_another_artifact() {
        let (conn, acquisition_id, environment_id, artifact_a, artifact_b) =
            python_runtime_mutation_fixture();
        let member_id = insert_python_runtime_member(
            &conn,
            (acquisition_id, environment_id, artifact_a),
            PythonRuntimeMemberInsert {
                status: "unresolved",
                installed_path: None,
                member_sha256: None,
                installed_sha256: None,
                installed_bytes_match: None,
            },
        )
        .unwrap();

        // The parent tuple for this member belongs to artifact A. A provider
        // row that combines it with artifact B violates the composite FK.
        let error = conn
            .execute(
                "INSERT INTO python_runtime_import_providers(
                   acquisition_id, environment_id, artifact_id, member_id,
                   import_name, binding_status
                 ) VALUES(?1, ?2, ?3, ?4, 'example.module', 'unresolved')",
                rusqlite::params![acquisition_id, environment_id, artifact_b, member_id],
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("FOREIGN KEY constraint failed"),
            "mismatched artifact/member ownership must fail its composite FK, got {error}"
        );
    }

    #[test]
    fn python_runtime_scope_checks_reject_invalid_direct_sql_rows_and_keep_unknowns() {
        let (conn, acquisition_id, _, _, _) = python_runtime_mutation_fixture();
        let insert_scope = |source_scope: &str,
                            scope_path: Option<&str>,
                            scope_depth: Option<i64>,
                            status: &str| {
            conn.execute(
                "INSERT INTO python_runtime_environments(
                   acquisition_id, source_scope, scope_path, scope_depth, status
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    acquisition_id,
                    source_scope,
                    scope_path,
                    scope_depth,
                    status,
                ],
            )
        };

        // The root, normal relative components, and unresolved scopes with
        // either incomplete or unresolved status are all representable.
        insert_scope(".", Some("."), Some(0), "incomplete").unwrap();
        insert_scope("src/pkg", Some("src/pkg"), Some(2), "archive_verified").unwrap();
        insert_scope("../missing", None, None, "unresolved").unwrap();
        insert_scope("../partial", None, None, "incomplete").unwrap();

        let invalid_scopes = [
            (
                "dot component",
                "src/./pkg",
                Some("src/./pkg"),
                Some(3),
                "incomplete",
            ),
            ("parent component", "..", Some(".."), Some(1), "incomplete"),
            (
                "embedded parent component",
                "src/../pkg",
                Some("src/../pkg"),
                Some(3),
                "incomplete",
            ),
            ("absolute path", "/src", Some("/src"), Some(1), "incomplete"),
            (
                "Windows drive path",
                "C:/src",
                Some("C:/src"),
                Some(2),
                "incomplete",
            ),
            (
                "Windows separator path",
                r"C:\src",
                Some(r"C:\src"),
                Some(1),
                "incomplete",
            ),
            (
                "verified but unresolved scope",
                "../verified",
                None,
                None,
                "archive_verified",
            ),
            (
                "conflicting but unresolved scope",
                "../conflicting",
                None,
                None,
                "conflicting",
            ),
        ];

        for (description, source_scope, scope_path, scope_depth, status) in invalid_scopes {
            let error = insert_scope(source_scope, scope_path, scope_depth, status).unwrap_err();
            assert!(
                error.to_string().contains("CHECK constraint failed"),
                "{description} must be rejected by a CHECK constraint, got {error}"
            );
        }

        let retained_unknowns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM python_runtime_environments
                 WHERE acquisition_id = ?1 AND scope_path IS NULL
                   AND status IN ('unresolved', 'incomplete')",
                [acquisition_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_unknowns, 2);
    }

    fn python_runtime_mutation_fixture() -> (Connection, i64, i64, i64, i64) {
        let conn = open_in_memory_cache();
        let workspace_id = "a".repeat(64);
        conn.execute(
            "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, 'python', 0, 1)",
            [&workspace_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO python_runtime_acquisitions(
               workspace_id, lang, generation, revision, evidence_digest
             ) VALUES(?1, 'python', 0, 1, zeroblob(32))",
            [&workspace_id],
        )
        .unwrap();
        let acquisition_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO python_runtime_environments(
               acquisition_id, source_scope, scope_path, scope_depth, status
             ) VALUES(?1, '.', '.', 0, 'incomplete')",
            [acquisition_id],
        )
        .unwrap();
        let environment_id = conn.last_insert_rowid();
        let mut artifact_ids = Vec::new();
        for archive_path in ["/archives/a.whl", "/archives/b.whl"] {
            conn.execute(
                "INSERT INTO python_runtime_artifacts(
                   environment_id, acquisition_id, archive_path, installed_root, status
                 ) VALUES(?1, ?2, ?3, '/site-packages', 'incomplete')",
                rusqlite::params![environment_id, acquisition_id, archive_path],
            )
            .unwrap();
            artifact_ids.push(conn.last_insert_rowid());
        }
        (
            conn,
            acquisition_id,
            environment_id,
            artifact_ids[0],
            artifact_ids[1],
        )
    }

    struct PythonRuntimeMemberInsert<'a> {
        status: &'a str,
        installed_path: Option<&'a str>,
        member_sha256: Option<&'a str>,
        installed_sha256: Option<&'a str>,
        installed_bytes_match: Option<i64>,
    }

    fn insert_python_runtime_member(
        conn: &Connection,
        (acquisition_id, environment_id, artifact_id): (i64, i64, i64),
        member: PythonRuntimeMemberInsert<'_>,
    ) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO python_runtime_artifact_members(
               artifact_id, environment_id, acquisition_id, archive_member_path,
               installed_path, member_sha256, installed_sha256,
               installed_bytes_match, member_role, status
             ) VALUES(?1, ?2, ?3, 'module.py', ?4, ?5, ?6, ?7, 'runtime', ?8)",
            rusqlite::params![
                artifact_id,
                environment_id,
                acquisition_id,
                member.installed_path,
                member.member_sha256,
                member.installed_sha256,
                member.installed_bytes_match,
                member.status,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    #[test]
    fn v125_aggregate_policy_evidence_is_not_promoted_to_v126() {
        let conn = create_current_baseline_without_migration();
        conn.execute_batch(
            "INSERT INTO policy_evaluations(
               base_tree_oid, policy_set_digest, options_digest,
               configuration_fingerprint, active_model_set_hash, engine_epoch,
               resolved_commit, published_at
             ) VALUES(
               '2222222222222222222222222222222222222222',
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               '3333333333333333333333333333333333333333', 100
             );
             INSERT INTO policy_evaluation_identities(evaluation_id, policy_id, finding_id)
             VALUES((SELECT evaluation_id FROM policy_evaluations), 'test.policy', zeroblob(32));",
        )
        .unwrap();
        for migration in POST_BASELINE_MIGRATIONS {
            conn.execute_batch(migration.sql).unwrap();
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM policy_evaluations", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "legacy aggregate evidence lacks per-policy completion and provenance"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM policy_evaluation_identities",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            schema_object_definitions_sha256(&conn).unwrap(),
            CURRENT_SCHEMA_OBJECTS_SHA256
        );
    }

    fn create_current_baseline_without_migration() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch(BASELINE_SCHEMA_SQL).unwrap();
        conn
    }

    fn create_legacy_cache(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
    }

    #[test]
    fn network_cache_policy_refuses_wal_unless_operator_explicitly_accepts_it() {
        let db_path = Path::new("/shared/repository/.bifrost/cache/bifrost_cache.db");

        let error = validate_network_cache_policy(db_path, Some("NFS"), false).unwrap_err();
        assert!(error.contains(&db_path.display().to_string()), "{error}");
        assert!(error.contains(crate::gitblob::CACHE_ROOT_ENV), "{error}");
        assert!(error.contains(ALLOW_NETWORK_CACHE_ENV), "{error}");
        assert!(validate_network_cache_policy(db_path, None, false).is_ok());
        assert!(validate_network_cache_policy(db_path, Some("NFS"), true).is_ok());
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
        let durable = error
            .find("BIFROST_CACHE_ROOT=<writable local root>")
            .unwrap();
        let transient = error.find("deliberately transient").unwrap();
        let relocate = error.find("BIFROST_CACHE_DIR=<writable dir>").unwrap();
        assert!(
            elevate < durable && durable < transient && transient < relocate,
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
    fn empty_subfloor_versions_are_recreated_at_the_current_schema() {
        for version in [62, 116] {
            let mut conn = Connection::open_in_memory().unwrap();
            configure_connection(&mut conn).unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();

            migrate(&mut conn).unwrap();

            assert_eq!(
                cache_migration_version(&conn).unwrap(),
                CURRENT_MIGRATION_VERSION
            );
            assert!(current_schema_is_valid(&conn).unwrap());
        }
    }

    #[test]
    fn pointer_transfer_migration_preserves_rows_indexes_and_cascade() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 129)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 128).unwrap();
        conn.execute("INSERT INTO blobs(blob_oid, lang, generation) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'go', 0)", []).unwrap();
        let blob = conn.last_insert_rowid();
        conn.execute("INSERT INTO resolution_fragment_interiors(blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state) VALUES(?1, 'go', 'go', 'pointer-test', zeroblob(32), 0, 2, 0, 'building')", [blob]).unwrap();
        conn.execute(
            "INSERT INTO resolution_type_transfers VALUES(?1, 1, 2, 3, 0, 0, 0, 0, NULL)",
            [blob],
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT value_transform FROM resolution_type_transfers WHERE blob_id=?1 AND rule=2",
                [blob],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        for code in [4, 5, 6, 7] {
            conn.execute(
                "INSERT INTO resolution_type_transfers VALUES(?1, 1, ?2, 3, 0, 0, 0, ?2, NULL)",
                rusqlite::params![blob, code],
            )
            .unwrap();
        }
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_transfers VALUES(?1, 1, 8, 3, 0, 0, 0, 8, NULL)",
                [blob]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_transfers VALUES(?1, 99, 2, 3, 0, 0, 0, 0, NULL)",
                [blob]
            )
            .is_err()
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        conn.execute("DELETE FROM blobs WHERE id=?1", [blob])
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_type_transfers",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn rust_import_scope_migration_preserves_baseline_blobs() {
        let mut conn = create_current_baseline_without_migration();
        conn.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
            .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rust', 0)",
            [],
        ).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        conn.prepare("SELECT native_scope FROM source_rust_import_targets")
            .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn reopening_current_schema_preserves_existing_rows() {
        let mut conn = open_in_memory_cache();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rust', 0)",
            [],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn policy_units_follow_their_seed_blob_and_enforce_partition_shape() {
        let conn = open_in_memory_cache();
        conn.execute_batch(
            "INSERT INTO analysis_epochs(lang, epoch, generation)
               VALUES('java', 'test', 7);
             INSERT INTO blobs(blob_oid, lang, generation)
               VALUES('1111111111111111111111111111111111111111', 'java', 7);
             INSERT INTO policy_units(
               policy_semantic_hash, family, partition_kind, seed_rel_path,
               seed_blob_oid, partition_digest, seed_blob_id, lang,
               configuration_fingerprint,
               active_model_set_hash, engine_epoch, completion, budget_mode,
               product_kind, product, read_set_digest, published_at
             ) VALUES(
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'match', 'seed', 'src/Main.java',
               '1111111111111111111111111111111111111111', '',
               (SELECT id FROM blobs
                  WHERE blob_oid = '1111111111111111111111111111111111111111'
                    AND lang = 'java'),
               'java',
               'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'complete', 'exhaustive', 'rows', '{\"rows\":[]}',
               zeroblob(32), 100
             );",
        )
        .unwrap();

        // A whole-policy unit covers the workspace, so naming a seed file
        // would make its key mean two different things.
        let seeded_whole = conn
            .execute(
                "INSERT INTO policy_units(
                   policy_semantic_hash, family, partition_kind, seed_rel_path,
                   seed_blob_oid, partition_digest, configuration_fingerprint,
                   active_model_set_hash,
                   engine_epoch, completion, budget_mode, product_kind, product,
                   read_set_digest, published_at
                 ) VALUES(
                   'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                   'match', 'whole', 'src/Main.java', '', '',
                   'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                   'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                   'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                   'complete', 'exhaustive', 'rows', '{}', zeroblob(32), 100
                 )",
                [],
            )
            .unwrap_err();
        assert!(seeded_whole.to_string().contains("CHECK constraint failed"));

        // An assert unit's question is narrower than the file it covers: it is
        // keyed by the subject rows it asserted over, and a row without that
        // digest would answer a question nobody asked. A file's findings are
        // also not a query's rows, so the two kinds must agree.
        for (partition_kind, partition_digest, product_kind) in [
            ("assert_file", "", "assert_file"),
            (
                "assert_file",
                "ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee",
                "rows",
            ),
            (
                "seed",
                "ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee",
                "rows",
            ),
            // A relational binding unit is keyed by the binding it executed,
            // because one policy runs one query per binding over the same seed
            // files; without it the second binding would read the first's rows.
            // Its product is that query's rows, not a file's findings.
            ("binding", "", "rows"),
            (
                "binding",
                "ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee",
                "assert_file",
            ),
        ] {
            let refused = conn
                .execute(
                    "INSERT INTO policy_units(
                       policy_semantic_hash, family, partition_kind, seed_rel_path,
                       seed_blob_oid, partition_digest, configuration_fingerprint,
                       active_model_set_hash,
                       engine_epoch, completion, budget_mode, product_kind, product,
                       read_set_digest, published_at
                     ) VALUES(
                       'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                       'assertion', ?1, 'src/Other.java',
                       '1111111111111111111111111111111111111111', ?2,
                       'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                       'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                       'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
                       'complete', 'exhaustive', ?3, '{}', zeroblob(32), 100
                     )",
                    rusqlite::params![partition_kind, partition_digest, product_kind],
                )
                .unwrap_err();
            assert!(
                refused.to_string().contains("CHECK constraint failed"),
                "{partition_kind}/{product_kind}: {refused}"
            );
        }

        // A binding unit is a seed unit narrowed by the binding it ran, so the
        // partition the schema admits carries a file, a blob and that name's
        // digest, and publishes rendered rows.
        conn.execute(
            "INSERT INTO policy_units(
               policy_semantic_hash, family, partition_kind, seed_rel_path,
               seed_blob_oid, partition_digest, seed_blob_id, lang,
               configuration_fingerprint, active_model_set_hash, engine_epoch,
               completion, budget_mode, product_kind, product, read_set_digest,
               published_at
             ) VALUES(
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'assertion', 'binding', 'src/Main.java',
               '1111111111111111111111111111111111111111',
               'ff11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               (SELECT id FROM blobs
                  WHERE blob_oid = '1111111111111111111111111111111111111111'
                    AND lang = 'java'),
               'java',
               'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'complete', 'exhaustive', 'rows', '{\"rows\":[]}', zeroblob(32), 100
             )",
            [],
        )
        .unwrap();

        // Only exhaustive, complete units are publishable at all.
        let bounded = conn
            .execute("UPDATE policy_units SET budget_mode = 'bounded'", [])
            .unwrap_err();
        assert!(bounded.to_string().contains("CHECK constraint failed"));

        // A product must be JSON, because that is the only thing a reader can
        // do with the one column SQL does not inspect.
        let opaque_product = conn
            .execute("UPDATE policy_units SET product = 'not json'", [])
            .unwrap_err();
        assert!(
            opaque_product
                .to_string()
                .contains("CHECK constraint failed")
        );

        conn.execute_batch(
            "INSERT INTO policy_read_keys(key_digest, kind, languages, rel_path, blob_oid)
               VALUES(zeroblob(32), 'file', 'java', 'src/Main.java',
                      '1111111111111111111111111111111111111111');
             INSERT INTO policy_unit_reads(unit_id, read_id)
               VALUES((SELECT unit_id FROM policy_units),
                      (SELECT read_id FROM policy_read_keys));
             INSERT INTO policy_evaluations(
               base_tree_oid, policy_set_digest, options_digest,
               configuration_fingerprint, active_model_set_hash, engine_epoch,
               resolved_commit, published_at
             ) VALUES(
               '2222222222222222222222222222222222222222',
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'bb11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'cc11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'dd11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'ee11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               '3333333333333333333333333333333333333333', 100
             );
             INSERT INTO policy_evaluation_policies(
               evaluation_id, policy_id, source_hash, semantic_hash,
               completion, completion_detail, qualified, qualification_detail,
               diagnostics
             ) VALUES(
               (SELECT evaluation_id FROM policy_evaluations), 'test.policy',
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee',
               'complete', '\"complete\"', 1, '', '[]'
             );
             INSERT INTO policy_evaluation_units(evaluation_id, policy_id, unit_id)
               VALUES((SELECT evaluation_id FROM policy_evaluations), 'test.policy',
                      (SELECT unit_id FROM policy_units));
             INSERT INTO policy_evaluation_identities(evaluation_id, policy_id, finding_id)
               VALUES((SELECT evaluation_id FROM policy_evaluations), 'test.policy',
                      zeroblob(32));",
        )
        .unwrap();

        // A finding identity is a fixed-width digest. A truncated one would
        // silently match nothing, which is a base finding reported as fixed
        // and a head finding reported as new.
        let short_identity = conn
            .execute(
                "INSERT INTO policy_evaluation_identities(evaluation_id, policy_id, finding_id)
                 VALUES((SELECT evaluation_id FROM policy_evaluations), 'test.policy',
                        zeroblob(16))",
                [],
            )
            .unwrap_err();
        assert!(
            short_identity
                .to_string()
                .contains("CHECK constraint failed")
        );

        conn.execute(
            "DELETE FROM blobs
             WHERE blob_oid = '1111111111111111111111111111111111111111'
               AND lang = 'java'",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM policy_units", [], |row| row
                .get::<_, usize>(0))
                .unwrap(),
            0,
            "a unit must follow the seed blob whose content it answered about"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM policy_unit_reads", [], |row| row
                .get::<_, usize>(0))
                .unwrap(),
            0,
            "a unit's read membership must go with the unit"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM policy_evaluation_units", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap(),
            0,
            "an evaluation's membership must go with the unit it named"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM policy_evaluations", [], |row| row
                .get::<_, usize>(
                0
            ))
            .unwrap(),
            1,
            "the evaluation row survives its units: what it concluded does not depend on \
             the per-file work that produced it"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM policy_evaluation_identities",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
            1,
            "and neither do the identities a later run joins against"
        );

        conn.execute("DELETE FROM policy_evaluations", []).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM policy_evaluation_identities",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
            0,
            "an identity belongs to its evaluation and goes with it"
        );
    }

    #[test]
    fn live_definition_views_enforce_publication_and_keep_indexed_lookups() {
        for state in PlannerStatisticsState::BOTH {
            live_definition_views_enforce_publication_and_keep_indexed_lookups_in(state);
        }
    }

    fn live_definition_views_enforce_publication_and_keep_indexed_lookups_in(
        state: PlannerStatisticsState,
    ) {
        let conn = open_in_memory_cache();
        let live_oid = "1111111111111111111111111111111111111111";
        conn.execute_batch(
            "INSERT INTO analysis_epochs(lang, epoch, generation)
               VALUES('java', 'test', 7);
             INSERT INTO blobs(blob_oid, lang, generation) VALUES
               ('1111111111111111111111111111111111111111', 'java', 7),
               ('2222222222222222222222222222222222222222', 'java', 6),
               ('3333333333333333333333333333333333333333', 'java', 7);
             INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             )
             SELECT id, lang, 0, 'pkg', 1, 0, 0, 0, 0, 0, 0, 0,
                    CASE WHEN blob_oid LIKE '3%' THEN 0 ELSE 1 END
             FROM blobs;
             INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, exact_fqn, normalized_fqn,
               simple_type_name, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             )
             SELECT id, lang, 1, 0, name, name, 'pkg', 'pkg.' || name,
                    'pkg.' || name, name, 0, 0, 1, 1
             FROM (
               SELECT id, lang, blob_oid,
                      CASE substr(blob_oid, 1, 1)
                        WHEN '1' THEN 'Live'
                        WHEN '2' THEN 'Stale'
                        ELSE 'Incomplete'
                      END AS name
               FROM blobs
             );",
        )
        .unwrap();

        for view in [
            "live_parsed_blobs",
            "live_code_units",
            "live_declarations",
            "live_definition_units",
        ] {
            let rows: Vec<String> = conn
                .prepare(&format!("SELECT blob_oid FROM {view}"))
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(
                rows,
                [live_oid],
                "{view} must expose only published live rows"
            );
        }

        state.install(&conn);
        let plan = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT blob_oid, unit_key
                 FROM live_declarations
                 WHERE lang = 'java' AND exact_fqn = 'pkg.Live'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("idx_code_units_lang_exact_fqn_declarations")),
            "exact live declaration lookup must use its partial index {state}: {plan:?}"
        );
        assert!(
            plan.iter().all(|step| !step.contains("SCAN units")),
            "exact live declaration lookup must not scan code_units {state}: {plan:?}"
        );
    }

    #[test]
    fn revisioned_workspace_projection_enforces_temporal_identity_and_indexed_membership() {
        for state in PlannerStatisticsState::BOTH {
            revisioned_workspace_projection_enforces_temporal_identity_and_indexed_membership_in(
                state,
            );
        }
    }

    fn revisioned_workspace_projection_enforces_temporal_identity_and_indexed_membership_in(
        state: PlannerStatisticsState,
    ) {
        let conn = open_in_memory_cache();
        conn.execute_batch(
            "INSERT INTO analysis_epochs(lang, epoch, generation)
               VALUES('java', 'test', 7);
             INSERT INTO blobs(blob_oid, lang, generation)
               VALUES('1111111111111111111111111111111111111111', 'java', 7);
             INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             )
             SELECT id, lang, 0, 'pkg', 1, 0, 0, 0, 0, 0, 0, 0, 1 FROM blobs;
             INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, simple_type_name, synthetic, is_type_alias,
               in_declarations, in_definition_lookup, fq_anchor_kind, fq_anchor_pop,
               fq_package_tail_segments, exact_fqn_tail, normalized_fqn_tail,
               exact_parent_fqn_tail, package_fqn_tail
             )
             SELECT id, lang, 1, 0, 'Live$1', 'Live$1', 'pkg', 'Live', 0, 0, 1, 1,
                    NULL, NULL, 1, 'pkg.Live$1', 'pkg.Live', 'pkg', 'pkg'
             FROM blobs;
             INSERT INTO unit_signatures(blob_id, lang, unit_key, ordinal, text)
               SELECT id, lang, 1, 0, 'class Live$1' FROM blobs;
             INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
               VALUES(
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 'java', 7, 1
               ), (
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 'java', 7, 2
               );
             INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
               VALUES(
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 'java', 7, 2
               );
             INSERT INTO workspace_file_versions(
               workspace_id, lang, generation, rel_path, blob_oid,
               projection_digest, valid_from, valid_until
             ) VALUES(
               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
               'java', 7, 'src/Live.java',
               '1111111111111111111111111111111111111111',
               'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
               1, 2
             );",
        )
        .unwrap();

        state.install(&conn);
        for (sql, expected_index) in [
            (
                "SELECT file_version_id FROM workspace_file_versions
                 WHERE workspace_id =
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                   AND lang = 'java' AND generation = 7
                   AND rel_path = 'src/Live.java'
                   AND valid_from <= 1
                   AND (valid_until IS NULL OR 1 < valid_until)",
                "idx_workspace_file_versions_snapshot_path",
            ),
            (
                "SELECT file_version_id FROM workspace_file_versions
                 WHERE workspace_id =
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                   AND lang = 'java' AND generation = 7
                   AND blob_oid = '1111111111111111111111111111111111111111'
                   AND valid_from <= 1
                 AND (valid_until IS NULL OR 1 < valid_until)",
                "idx_workspace_file_versions_snapshot_blob",
            ),
        ] {
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert!(
                plan.iter().any(|step| step.contains(expected_index)),
                "relational lookup must use {expected_index} {state}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .all(|step| !step.contains("SCAN workspace_file_versions")),
                "snapshot lookup must not scan workspace_file_versions {state}: {plan:?}"
            );
        }

        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM workspace_file_versions
                 WHERE valid_from <= 1 AND (valid_until IS NULL OR 1 < valid_until)",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM workspace_file_versions
                 WHERE valid_from <= 2 AND (valid_until IS NULL OR 2 < valid_until)",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            0
        );

        let invalid_interval = conn.execute(
            "INSERT INTO workspace_file_versions(
               workspace_id, lang, generation, rel_path, blob_oid,
               projection_digest, valid_from, valid_until
             ) VALUES(?1, 'java', 7, 'src/Bad.java', ?2, ?3, 2, 2)",
            rusqlite::params![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "1111111111111111111111111111111111111111",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        );
        assert!(
            invalid_interval.is_err(),
            "empty validity intervals are invalid"
        );

        let invalid_anchor = conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup, fq_anchor_kind, fq_anchor_pop
             ) VALUES(?1, 'java', 2, 0, 'Bad', 'Bad', 'pkg', 0, 0, 1, 1,
                      'own_module', NULL)",
            ["1111111111111111111111111111111111111111"],
        );
        assert!(
            invalid_anchor.is_err(),
            "anchor kind requires its paired pop"
        );
        let duplicate_normalized = conn.execute(
            "INSERT INTO code_units(
               blob_oid, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup,
               exact_fqn_tail, normalized_fqn_tail
             ) VALUES(?1, 'java', 3, 0, 'Bad', 'Bad', 'pkg', 0, 0, 1, 1,
                      'pkg.Bad', 'pkg.Bad')",
            ["1111111111111111111111111111111111111111"],
        );
        assert!(
            duplicate_normalized.is_err(),
            "identity normalization is represented by NULL, not a duplicate string"
        );
    }

    #[test]
    fn writer_page_cache_environment_is_process_local() {
        const EXPECTED_ENV: &str = "BIFROST_TEST_WRITER_CACHE_EXPECTED";
        if let Ok(expected) = std::env::var(EXPECTED_ENV) {
            let temp = tempfile::tempdir().unwrap();
            let result = open_unified_connection(&temp.path().join(cache_db_file_name()));
            if expected == "invalid" {
                let error = result.unwrap_err();
                assert!(error.contains(WRITER_PAGE_CACHE_ENV), "{error}");
                assert!(error.contains("positive integer"), "{error}");
            } else {
                let conn = result.unwrap();
                let actual: i64 = conn
                    .query_row("PRAGMA cache_size", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(actual, expected.parse::<i64>().unwrap());
                let mut memory = Connection::open_in_memory().unwrap();
                configure_connection(&mut memory).unwrap();
                let actual: i64 = memory
                    .query_row("PRAGMA cache_size", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(actual, expected.parse::<i64>().unwrap());
            }
            return;
        }

        for (value, expected) in [
            (None, "-524288"),
            (Some("8192"), "-8192"),
            (Some("16384"), "-16384"),
            (Some(""), "invalid"),
            (Some("0"), "invalid"),
            (Some("-1"), "invalid"),
            (Some("eight"), "invalid"),
            (Some("2147483648"), "invalid"),
        ] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "cache_db::tests::writer_page_cache_environment_is_process_local",
                    "--nocapture",
                ])
                .env(EXPECTED_ENV, expected);
            match value {
                Some(value) => {
                    child.env(WRITER_PAGE_CACHE_ENV, value);
                }
                None => {
                    child.env_remove(WRITER_PAGE_CACHE_ENV);
                }
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "writer cache {value:?}: {output:?}"
            );
        }
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
        assert_eq!(connection_page_size(&conn), CACHE_PAGE_SIZE_BYTES);
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

    fn connection_page_size(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
            .unwrap()
    }

    #[test]
    fn fresh_cache_store_uses_cache_page_size() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());

        let conn = open_unified_connection(&db_path).unwrap();

        assert_eq!(connection_page_size(&conn), CACHE_PAGE_SIZE_BYTES);
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
        assert!(quick_check_is_ok(&conn).unwrap());
    }

    #[test]
    fn populated_wal_store_keeps_legacy_page_size_without_losing_rows_or_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE existing(value TEXT PRIMARY KEY) WITHOUT ROWID, STRICT;
             INSERT INTO existing VALUES('alpha'), ('beta'), ('gamma');
             PRAGMA application_id=2462;
             PRAGMA user_version=1234;",
        )
        .unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );

        // Keep a separate reader transaction open while the writer is
        // configured. The legacy page-size path tried to switch this WAL
        // store to rollback mode before VACUUM, which waited on this reader.
        let reader = Connection::open(&db_path).unwrap();
        reader
            .execute_batch("PRAGMA journal_mode=WAL; BEGIN;")
            .unwrap();
        assert_eq!(
            reader
                .query_row("SELECT COUNT(*) FROM existing", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );

        // The limit is deliberately generous for a non-benchmark regression,
        // while still rejecting the old multi-second reader/VACUUM wait. If a
        // pre-fix implementation is ever tested, release the reader before
        // joining the worker so the failure remains bounded.
        let (configured_tx, configured_rx) = std::sync::mpsc::channel();
        let configure_started = Instant::now();
        let configure_thread = thread::spawn(move || {
            let mut conn = conn;
            let result = configure_connection(&mut conn);
            configured_tx
                .send((conn, result, configure_started.elapsed()))
                .unwrap();
        });
        let configure_limit = Duration::from_secs(10);
        let (mut conn, configure_result, configure_elapsed) = match configured_rx
            .recv_timeout(configure_limit)
        {
            Ok(completion) => {
                configure_thread.join().unwrap();
                completion
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                reader.execute_batch("ROLLBACK").unwrap();
                let _ = configure_thread.join();
                panic!(
                    "configure_connection exceeded {configure_limit:?} while a reader transaction was open"
                );
            }
            Err(error) => {
                reader.execute_batch("ROLLBACK").unwrap();
                let _ = configure_thread.join();
                panic!("configure_connection worker disconnected: {error}");
            }
        };
        reader.execute_batch("ROLLBACK").unwrap();
        configure_result.unwrap();
        assert!(
            configure_elapsed < configure_limit,
            "configure_connection took {configure_elapsed:?} with an active reader"
        );

        assert_eq!(
            connection_page_size(&conn),
            4096,
            "an existing populated store must not be rebuilt for page-size tuning"
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal",
            "the upgrade must leave the store back in WAL mode"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM existing", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            3,
            "connection setup must preserve existing rows"
        );
        assert_eq!(
            conn.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2462,
            "connection setup must preserve SQLite metadata"
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1234,
            "connection setup must preserve the schema version metadata"
        );
        assert!(quick_check_is_ok(&conn).unwrap());

        // Reconfiguring the same legacy store is safe and remains rewrite-free.
        configure_connection(&mut conn).unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert!(quick_check_is_ok(&conn).unwrap());
    }

    #[test]
    fn populated_rollback_store_keeps_legacy_page_size() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let mut conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE existing(value TEXT PRIMARY KEY) WITHOUT ROWID, STRICT;
             INSERT INTO existing VALUES('alpha');
             PRAGMA application_id=2462;
             PRAGMA user_version=5678;",
        )
        .unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "delete"
        );

        configure_connection(&mut conn).unwrap();

        assert_eq!(
            connection_page_size(&conn),
            4096,
            "an existing populated store must not be rebuilt for page-size tuning"
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM existing", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2462
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5678
        );
        assert!(quick_check_is_ok(&conn).unwrap());

        configure_connection(&mut conn).unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert!(quick_check_is_ok(&conn).unwrap());
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
        let mut conn = open_in_memory_cache();
        conn.execute_batch("DROP TABLE semantic_pack_active_state;")
            .unwrap();
        conn.pragma_update(None, "user_version", CURRENT_MIGRATION_VERSION)
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
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
    fn first_unified_open_removes_only_idle_legacy_analyzer_cache_after_migration() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".bifrost");
        std::fs::create_dir(&cache_dir).unwrap();
        create_legacy_cache(&cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME));
        create_legacy_cache(&cache_dir.join(LEGACY_ANALYZER_DB_FILE_NAME));

        let unified = cache_dir.join(cache_db_file_name());
        let connection = open_unified_connection(&unified).unwrap();

        assert!(unified_cache_initialized(&connection).unwrap());
        assert!(cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME).exists());
        assert!(!cache_dir.join(LEGACY_ANALYZER_DB_FILE_NAME).exists());
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
}
