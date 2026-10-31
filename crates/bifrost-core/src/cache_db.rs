//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, OnceLock, Weak};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rusqlite::ffi::ErrorCode;
#[cfg(test)]
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

pub mod sql_profile;

use sql_profile::ConnectionRole;

pub type Result<T> = std::result::Result<T, String>;

/// Read `BIFROST_UNSAFE_NO_FSYNC` once on first use.
/// Only `1` enables it. Analyzer caches and semantic-pack catalogs then skip
/// fsync and use SQLite synchronous=OFF. This is meant for disposable CI
/// machines: a host crash can corrupt those stores.
fn unsafe_no_fsync() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("BIFROST_UNSAFE_NO_FSYNC").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

/// Whether this blob receives the full publication consistency checks (#6390).
/// Tests and test-support always validate; production samples one blob in 64.
/// The environment override is read once and shared with the SQL seal function.
pub fn seal_validates(blob_id: i64) -> bool {
    static ALL: OnceLock<bool> = OnceLock::new();
    cfg!(any(test, feature = "test-support"))
        || *ALL.get_or_init(|| {
            std::env::var_os("BIFROST_SEAL_VALIDATION").as_deref()
                == Some(std::ffi::OsStr::new("all"))
        })
        || blob_id % 64 == 0
}

/// Install `bifrost_seal_validates`, which the publication-state seal triggers
/// call. Store writers register it when they open; a harness that plans
/// production write SQL on another connection registers it the same way.
pub fn register_seal_validation(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "bifrost_seal_validates",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| Ok(seal_validates(context.get::<i64>(0)?)),
    )
}

/// SQLite synchronous setting for cache stores; see `unsafe_no_fsync`.
pub fn sqlite_synchronous() -> &'static str {
    if unsafe_no_fsync() { "OFF" } else { "NORMAL" }
}

/// Sync a cache or catalog file; see `unsafe_no_fsync` for the unsafe CI override.
pub fn sync_file(file: &File) -> std::io::Result<()> {
    if unsafe_no_fsync() {
        Ok(())
    } else {
        file.sync_all()
    }
}

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
/// Name prefix of a store copy staged for an upgrade, and of its SQLite
/// sidecars. Nothing else in a cache directory starts with it.
const STAGED_UPGRADE_PREFIX: &str = ".bifrost-cache-import";
/// The lock that one process in a cache directory holds while it stages an
/// upgrade. The file is never deleted, so every process locks the same inode.
const UPGRADE_LOCK_FILE_NAME: &str = ".bifrost-cache-upgrade.lock";
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
const CURRENT_MIGRATION_VERSION: i64 =
    POST_BASELINE_MIGRATIONS[POST_BASELINE_MIGRATIONS.len() - 1].version;
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
    CacheMigration {
        version: 139,
        sql: include_str!("../migrations/cache/0139-native-declared-type-arguments.sql"),
    },
    CacheMigration {
        version: 140,
        sql: include_str!("../migrations/cache/0140-dependency-file-evidence.sql"),
    },
    CacheMigration {
        version: 141,
        sql: include_str!("../migrations/cache/0141-native-type-argument-fk-index.sql"),
    },
    CacheMigration {
        version: 142,
        sql: include_str!("../migrations/cache/0142-policy-unit-content-identity.sql"),
    },
    CacheMigration {
        version: 143,
        sql: include_str!("../migrations/cache/0143-parse-completeness.sql"),
    },
    CacheMigration {
        version: 144,
        sql: include_str!("../migrations/cache/0144-structural-recovered-regions.sql"),
    },
    CacheMigration {
        version: 145,
        sql: include_str!("../migrations/cache/0145-native-declared-type-arguments.sql"),
    },
    CacheMigration {
        version: 146,
        sql: include_str!("../migrations/cache/0146-native-kotlin-jvm-facts.sql"),
    },
    CacheMigration {
        version: 147,
        sql: include_str!("../migrations/cache/0147-resolved-file-import-edges.sql"),
    },
    CacheMigration {
        version: 148,
        sql: include_str!("../migrations/cache/0148-incremental-file-import-edges.sql"),
    },
    CacheMigration {
        version: 149,
        sql: include_str!("../migrations/cache/0149-structured-import-candidate-dependencies.sql"),
    },
    CacheMigration {
        version: 150,
        sql: include_str!("../migrations/cache/0150-import-ordinal-edge-facts.sql"),
    },
    CacheMigration {
        version: 151,
        sql: include_str!("../migrations/cache/0151-name-granular-import-dependencies.sql"),
    },
    CacheMigration {
        version: 152,
        sql: include_str!("../migrations/cache/0152-import-edge-pair-reconciliation.sql"),
    },
    CacheMigration {
        version: 153,
        sql: include_str!("../migrations/cache/0153-rust-import-input-digests.sql"),
    },
    CacheMigration {
        version: 154,
        sql: include_str!("../migrations/cache/0154-cpp-base-access.sql"),
    },
    CacheMigration {
        version: 155,
        sql: include_str!("../migrations/cache/0155-rust-crate-member-paths.sql"),
    },
    CacheMigration {
        version: 156,
        sql: include_str!("../migrations/cache/0156-target-scoped-rust-gap-candidates.sql"),
    },
    CacheMigration {
        version: 157,
        sql: include_str!("../migrations/cache/0157-resolution-unit-summaries.sql"),
    },
    CacheMigration {
        version: 158,
        sql: include_str!("../migrations/cache/0158-rust-module-self-imports.sql"),
    },
    CacheMigration {
        version: 159,
        sql: include_str!("../migrations/cache/0159-rust-generated-attribute-surfaces.sql"),
    },
    CacheMigration {
        version: 160,
        sql: include_str!("../migrations/cache/0160-kotlin-package-reference-choice.sql"),
    },
    CacheMigration {
        version: 161,
        sql: include_str!("../migrations/cache/0161-shared-package-reference-token.sql"),
    },
    CacheMigration {
        version: 162,
        sql: include_str!("../migrations/cache/0162-generic-formal-positions.sql"),
    },
    CacheMigration {
        version: 163,
        sql: include_str!("../migrations/cache/0163-kotlin-scala-named-argument-labels.sql"),
    },
    CacheMigration {
        version: 164,
        sql: include_str!("../migrations/cache/0164-php-include-path-kinds.sql"),
    },
    CacheMigration {
        version: 165,
        sql: include_str!("../migrations/cache/0165-semantic-ir-rows.sql"),
    },
    CacheMigration {
        version: 166,
        sql: include_str!("../migrations/cache/0166-rust-reason-owner-source-site-index.sql"),
    },
    CacheMigration {
        version: 167,
        sql: include_str!("../migrations/cache/0167-semantic-ir-partial-flows.sql"),
    },
    CacheMigration {
        version: 168,
        sql: include_str!("../migrations/cache/0168-rust-derive-helper-attributes.sql"),
    },
    CacheMigration {
        version: 169,
        sql: include_str!("../migrations/cache/0169-go-rename-import-declaration-range.sql"),
    },
    CacheMigration {
        version: 170,
        sql: include_str!("../migrations/cache/0170-go-package-unit-key.sql"),
    },
    CacheMigration {
        version: 171,
        sql: include_str!(
            "../migrations/cache/0171-semantic-ir-partial-flow-crossed-calls-and-relation-proof.sql"
        ),
    },
    CacheMigration {
        version: 172,
        sql: include_str!("../migrations/cache/0172-root-import-activation-ordinal.sql"),
    },
    CacheMigration {
        version: 173,
        sql: include_str!("../migrations/cache/0173-rust-unit-summary-rows.sql"),
    },
    CacheMigration {
        version: 174,
        sql: include_str!("../migrations/cache/0174-jvm-external-owner-inventory.sql"),
    },
    CacheMigration {
        version: 175,
        sql: include_str!("../migrations/cache/0175-contextual-callable-parameter-lists.sql"),
    },
    CacheMigration {
        version: 176,
        sql: include_str!("../migrations/cache/0176-policy-evaluation-completion-labels.sql"),
    },
    CacheMigration {
        version: 177,
        sql: include_str!("../migrations/cache/0177-resolution-member-owner-name.sql"),
    },
    CacheMigration {
        version: 178,
        sql: include_str!("../migrations/cache/0178-semantic-ir-residual-conversion.sql"),
    },
    CacheMigration {
        version: 179,
        sql: include_str!("../migrations/cache/0179-generic-formal-defaults.sql"),
    },
    CacheMigration {
        version: 180,
        sql: include_str!("../migrations/cache/0180-executable-scope-owners.sql"),
    },
    CacheMigration {
        version: 181,
        sql: include_str!("../migrations/cache/0181-type-constructor-productions.sql"),
    },
    CacheMigration {
        version: 182,
        sql: include_str!("../migrations/cache/0182-summary-profile-validity.sql"),
    },
    CacheMigration {
        version: 183,
        sql: include_str!("../migrations/cache/0183-go-struct-field-tags.sql"),
    },
    CacheMigration {
        version: 184,
        sql: include_str!("../migrations/cache/0184-rust-macro-input-cfg.sql"),
    },
    CacheMigration {
        version: 185,
        sql: include_str!("../migrations/cache/0185-static-type-object-transfers.sql"),
    },
    CacheMigration {
        version: 186,
        sql: include_str!("../migrations/cache/0186-jvm-alias-member-index.sql"),
    },
    CacheMigration {
        version: 187,
        sql: include_str!("../migrations/cache/0187-rust-crate-public-module-reachability.sql"),
    },
    CacheMigration {
        version: 188,
        sql: include_str!("../migrations/cache/0188-declaration-access-boundaries.sql"),
    },
    CacheMigration {
        version: 189,
        sql: include_str!("../migrations/cache/0189-root-import-publication.sql"),
    },
    CacheMigration {
        version: 190,
        sql: include_str!("../migrations/cache/0190-shared-summary-placements.sql"),
    },
    CacheMigration {
        version: 191,
        sql: include_str!("../migrations/cache/0191-policy-semantic-replay-jsonb.sql"),
    },
    CacheMigration {
        version: 192,
        sql: include_str!("../migrations/cache/0192-rust-macro-input-name.sql"),
    },
    CacheMigration {
        version: 193,
        sql: include_str!("../migrations/cache/0193-class-set-owner-storage-identity.sql"),
    },
    CacheMigration {
        version: 194,
        sql: include_str!("../migrations/cache/0194-rust-canonical-binding-targets.sql"),
    },
    CacheMigration {
        version: 195,
        sql: include_str!("../migrations/cache/0195-rust-binding-authority.sql"),
    },
    CacheMigration {
        version: 196,
        sql: include_str!("../migrations/cache/0196-python-environment-summaries.sql"),
    },
    CacheMigration {
        version: 197,
        sql: include_str!("../migrations/cache/0197-rust-expanding-attribute-contexts.sql"),
    },
    CacheMigration {
        version: 198,
        sql: include_str!("../migrations/cache/0198-jvm-package-private-visibility.sql"),
    },
    CacheMigration {
        version: 199,
        sql: include_str!("../migrations/cache/0199-temporal-binding-inputs.sql"),
    },
    CacheMigration {
        version: 200,
        sql: include_str!("../migrations/cache/0200-python-reverse-inputs.sql"),
    },
    CacheMigration {
        version: 201,
        sql: include_str!("../migrations/cache/0201-python-member-inputs.sql"),
    },
    CacheMigration {
        version: 202,
        sql: include_str!("../migrations/cache/0202-python-member-operations.sql"),
    },
    CacheMigration {
        version: 203,
        sql: include_str!("../migrations/cache/0203-csharp-compilation-membership.sql"),
    },
    CacheMigration {
        version: 204,
        sql: include_str!("../migrations/cache/0204-rust-inherent-impl-subjects.sql"),
    },
    CacheMigration {
        version: 205,
        sql: include_str!("../migrations/cache/0205-shared-package-member-names.sql"),
    },
    CacheMigration {
        version: 206,
        sql: include_str!("../migrations/cache/0206-go-domain-contexts.sql"),
    },
    CacheMigration {
        version: 207,
        sql: include_str!("../migrations/cache/0207-native-visibility-definition-kinds.sql"),
    },
    CacheMigration {
        version: 208,
        sql: include_str!("../migrations/cache/0208-workspace-source-refusals.sql"),
    },
    CacheMigration {
        version: 209,
        sql: include_str!("../migrations/cache/0209-python-environment-source-inputs.sql"),
    },
    CacheMigration {
        version: 210,
        sql: include_str!("../migrations/cache/0210-cpp-namespace-aliases.sql"),
    },
    CacheMigration {
        version: 211,
        sql: include_str!("../migrations/cache/0211-procedure-dispatch-site-ordinal.sql"),
    },
    CacheMigration {
        version: 212,
        sql: include_str!("../migrations/cache/0212-declaration-read-identity.sql"),
    },
    CacheMigration {
        version: 213,
        sql: include_str!("../migrations/cache/0213-drop-redundant-reverse-gap-site-index.sql"),
    },
    CacheMigration {
        version: 215,
        sql: include_str!("../migrations/cache/0215-sample-seal-validation.sql"),
    },
    CacheMigration {
        version: 216,
        sql: include_str!("../migrations/cache/0216-rust-unresolved-impl-half-declarations.sql"),
    },
    CacheMigration {
        version: 217,
        sql: include_str!("../migrations/cache/0217-csharp-compilation-metadata.sql"),
    },
    CacheMigration {
        version: 218,
        sql: include_str!("../migrations/cache/0218-policy-unit-snapshots.sql"),
    },
    CacheMigration {
        version: 219,
        sql: include_str!("../migrations/cache/0219-deferred-member-selection.sql"),
    },
    CacheMigration {
        version: 220,
        sql: include_str!("../migrations/cache/0220-workspace-fact-reads.sql"),
    },
    CacheMigration {
        version: 221,
        sql: include_str!("../migrations/cache/0221-compilation-imports.sql"),
    },
    CacheMigration {
        version: 222,
        sql: include_str!("../migrations/cache/0222-field-slot-exact-result-sources.sql"),
    },
    CacheMigration {
        version: 223,
        sql: include_str!("../migrations/cache/0223-overload-discriminator.sql"),
    },
    CacheMigration {
        version: 224,
        sql: include_str!("../migrations/cache/0224-csharp-compilation-symbols.sql"),
    },
    CacheMigration {
        version: 225,
        sql: include_str!("../migrations/cache/0225-blob-parse-variant.sql"),
    },
];

static CACHE_DB_FILE_NAME: Lazy<String> =
    Lazy::new(|| cache_db_file_name_for_version(CURRENT_MIGRATION_VERSION));

/// The generated final schema and migration-owned seeds for an empty store.
/// The baseline and compatible migration chain remain authoritative; the
/// generator and historical parity test reject a snapshot that drifts from them.
const CURRENT_FRESH_SCHEMA_SQL: &str = include_str!("../migrations/cache/current-schema.sql");

/// Expected objects for validating an upgraded store. Building this small,
/// schema-owned reference must not replay the historical ALTER TABLE chain.
static CURRENT_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open current schema connection");
    conn.execute_batch(CURRENT_FRESH_SCHEMA_SQL)
        .expect("create current fresh schema");
    schema_object_definitions(&conn).expect("read current schema objects")
});
// SHA-256 of `schema_object_definitions` for the schema produced by every
// migration above, after `normalize_schema_sql` removes SQL whitespace.
// A current store validates its actual schema against this
// pinned identity without rebuilding all historical schemas in a second,
// in-memory database on every process start. The regression test below derives
// the value through SQLite and forces this constant to move with a migration.
const CURRENT_SCHEMA_OBJECTS_SHA256: [u8; 32] = [
    14, 148, 100, 134, 47, 165, 2, 230, 28, 119, 76, 156, 104, 53, 82, 168, 77, 220, 151, 196, 70,
    17, 233, 149, 40, 105, 76, 233, 55, 119, 174, 139,
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
/// The writer prepares each hot table's insert at up to three row counts
/// (bifrost-store's `row_batch`), on top of the statements every reader also
/// uses, so its cache holds more. Still one bound per connection.
const WRITER_PREPARED_STATEMENT_CACHE_CAPACITY: usize = 1024;
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
static PROCESS_LOCAL_STARTUP_CLEANUP_ATTEMPTS: Lazy<Mutex<HashSet<PathBuf>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// How long the retained store from another schema version may go untouched
/// before collection removes it.
pub const VERSION_STORE_GRACE_SECS: i64 = 14 * 24 * 3600;
/// The store file this build owns: `bifrost_cache.v{schema version}.db`.
///
/// The schema version belongs in the name rather than only in the file's
/// `user_version`. A single shared file migrates in place, so the newest build
/// to touch it decides for every checkout of the repository, and older builds
/// then refuse the whole file (issue #1589). Naming the file by its schema
/// instead lets versions sit side by side: each build opens exactly its own,
/// and the row-level design already keys rather than migrates everything else.
/// Collection keeps at most one other versioned store, chosen by recent use,
/// so two stores can serve checkouts of different versions at a time.
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

/// Remove excess versioned stores and expire the retained alternate after the
/// grace period.
///
/// The current store is never a candidate. Among every other recognized store
/// at or above the baseline, the most recently used is the sole survivor while
/// within the grace period; ties go to the higher schema version. Sub-floor
/// stores and every other candidate go through idle-safe deletion regardless
/// of age. The newest mtime across the store and its sidecars represents use
/// because WAL activity may not update the main database file.
pub fn sweep_disused_version_stores(cache_dir: &Path) -> Result<Vec<PathBuf>> {
    let stores = version_store_paths_to_remove(cache_dir)?;
    remove_version_stores(&stores)
}

fn version_store_paths_to_remove(cache_dir: &Path) -> Result<Vec<PathBuf>> {
    let now = now_unix_seconds();
    let mut stores = Vec::new();
    let mut eligible = Vec::new();
    for entry in std::fs::read_dir(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))? {
        let entry = entry.map_err(|err| format!("cache DB I/O error: {err}"))?;
        let name = entry.file_name();
        let Some(version) = name.to_str().and_then(store_file_version) else {
            continue;
        };
        if name == std::ffi::OsStr::new(cache_db_file_name()) {
            continue;
        }
        let store = entry.path();
        if version < BASELINE_MIGRATION_VERSION {
            stores.push(store);
            continue;
        }
        let last_use = last_store_use_unix_seconds(&store)?;
        eligible.push((version, store, last_use));
    }

    // Each version names exactly one file, so (last use, version) is a total
    // order and the survivor is deterministic.
    let survivor_index = eligible
        .iter()
        .enumerate()
        .max_by_key(|(_, (version, _, last_use))| (*last_use, *version))
        .map(|(index, _)| index);
    for (index, (_, store, last_use)) in eligible.into_iter().enumerate() {
        if Some(index) != survivor_index || last_use + VERSION_STORE_GRACE_SECS <= now {
            stores.push(store);
        }
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
    let mut conn = Connection::open_with_flags(db_path, flags)?;
    if !flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY) {
        register_seal_validation(&conn)?;
        conn.set_transaction_behavior(TransactionBehavior::Immediate);
    }
    sql_profile::install(&conn, role);
    Ok(conn)
}

/// The in-memory store [`crate::cache_db`]'s callers fall back to when no temp
/// file can back an ephemeral analyzer store. It has no path, so it cannot go
/// through [`open_store_connection`], and it is the only other way a process
/// reaches a store.
pub fn open_in_memory_store_connection() -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    register_seal_validation(&conn)?;
    conn.set_transaction_behavior(TransactionBehavior::Immediate);
    sql_profile::install(&conn, ConnectionRole::Ephemeral);
    Ok(conn)
}

pub fn open_unified_connection(db_path: &Path) -> Result<Connection> {
    let template_dir = crate::sqlite_template::template_dir();
    open_unified_connection_with_template_dir(db_path, template_dir.as_deref())
}

/// [`open_unified_connection`] with the store-template directory as an
/// argument. A test that asserts what a fresh store looks like passes its own
/// empty directory: in the machine template directory, a template that another
/// run published would satisfy the test without running the fresh-build path.
fn open_unified_connection_with_template_dir(
    db_path: &Path,
    template_dir: Option<&Path>,
) -> Result<Connection> {
    disable_sqlite_memory_statistics();
    {
        let _scope = crate::profiling::scope("cache_db.validate_filesystem");
        validate_writable_cache_filesystem(db_path)?;
    }
    open_unified_connection_unclassified(db_path, template_dir).map_err(|error| {
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

fn open_unified_connection_unclassified(
    db_path: &Path,
    template_dir: Option<&Path>,
) -> Result<Connection> {
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
    let disused_stores = startup_cleanup(&db_path);
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
    let seeded = {
        let _scope = crate::profiling::scope("cache_db.seed_from_template");
        seed_new_store_from_template(&db_path, template_dir)?
    };
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
        !seeded && unified_cache_initialized(&conn)?
    };
    {
        let _scope = crate::profiling::scope("cache_db.migrate");
        migrate(&mut conn)?;
    }
    if seeded {
        // The template's cadence started when the template was built.
        start_collection_cadence(&conn)?;
    }
    if !initialized_before_open {
        delete_legacy_cache_files(&db_path);
    }
    if let Some(stores) = disused_stores
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

/// Once per process and cache directory, remove the copies interrupted
/// upgrades left behind, and return the disused version stores to remove after
/// this build's store has opened.
fn startup_cleanup(db_path: &Path) -> Option<Vec<PathBuf>> {
    if db_path.file_name() != Some(std::ffi::OsStr::new(cache_db_file_name())) {
        return None;
    }
    let cache_dir = db_path.parent()?;
    let should_attempt = PROCESS_LOCAL_STARTUP_CLEANUP_ATTEMPTS
        .lock()
        .expect("cache startup cleanup mutex poisoned")
        .insert(cache_dir.to_path_buf());
    if !should_attempt {
        return None;
    }
    if let Err(error) = collect_abandoned_staged_copies(cache_dir) {
        eprintln!("Bifrost cache cleanup of interrupted upgrades skipped: {error}");
    }
    match version_store_paths_to_remove(cache_dir) {
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
    let conn = open_readonly_store_connection(
        db_path,
        ConnectionRole::Reader,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        "cache DB read-only SQLite error",
    )?;
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

fn open_readonly_store_connection(
    db_path: &Path,
    role: ConnectionRole,
    flags: OpenFlags,
    error_context: &str,
) -> Result<Connection> {
    disable_sqlite_memory_statistics();
    ensure_safe_cache_path(db_path)?;
    let db_path = canonicalize_cache_db_parent(db_path)?;
    let conn = open_store_connection(&db_path, flags, role)
        .map_err(|err| format!("{error_context}: {err}"))?;
    install_busy_timeout(&conn)?;
    Ok(conn)
}

/// Open an initialized cache with a read-only main database and a writable
/// temporary schema.
///
/// The SQLite read-only flag prevents persistent writes, while a writable TEMP
/// schema permits connection-local membership and FTS tables.
pub fn open_readonly_temp_connection(db_path: &Path) -> Result<Connection> {
    let conn = open_readonly_store_connection(
        db_path,
        ConnectionRole::SessionReader,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW | READER_THREADING,
        "cache DB active-session SQLite error",
    )?;
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
    let conn = open_readonly_store_connection(
        db_path,
        ConnectionRole::StreamingReader,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW | READER_THREADING,
        "cache DB streaming read-only SQLite error",
    )?;
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

/// Memory-map window for interactive read-only connections, in bytes. A
/// mapping's file-backed pages are shared by pooled readers of the same
/// store, so those pages do not multiply with the reader count the way the
/// private page cache does. Each reader still pays for its own page tables.
/// The reasoning and measurements are in `configure_readonly_page_cache`.
#[doc(hidden)]
pub const READER_MMAP_SIZE_BYTES: i64 = 2 * 1024 * 1024 * 1024;

/// Mapping budget borrowed only for crate derivation, restored on pool checkin.
///
/// Measured 2026-10-22 on MinasMorgulWSL (120 logical CPUs, ZFS), deriving
/// all 31 root-package test/bin/example crates of the Bifrost workspace at 92f1099b31
/// concurrently against a copy of its finished 31.7 GB store. These are wave
/// replays, not full cold builds; timings include debugger pauses and host
/// contention. Cache/map columns are MiB/GiB; memory columns are GiB.
///   cache/map       wave s    bench bindings s    peak RSS    peak PSS
///     8/2           179.70          170.82            8.23        8.10
///     8/32          113.50           54.94           13.31        8.27
///     8/2 repeat    210.60          201.80            9.08        8.34
///     8/32 repeat    38.84           24.89           13.23        8.69
/// Wave read calls fell from about 52 million (1 TiB of logical reads) to
/// 3,500-3,700 (0.09 GiB); storage-read counters stayed near 2.1-2.3 GiB.
/// Whole-command system CPU fell from 3,862-4,435 to 85-122 seconds. SQLite's
/// direct overflow reads bypass its page cache, but its VFS serves in-window
/// reads from the mapping. Keep the page cache at 8 MiB: larger private caches
/// did not remove that traffic and added 1.7-5.9 GiB of anonymous residency.
///
/// File pages are shared, but every mapping has its own page tables. The
/// larger window added about 0.8 GiB of shared file residency and 0.13 GiB of
/// page tables in this wave. Applying it to up to 120 pooled interactive
/// readers of a 30 GB store could cost several GiB of page tables; that needs
/// its own measurement. Ordinary readers therefore keep their smaller map.
#[doc(hidden)]
pub const DERIVATION_MMAP_SIZE_BYTES: i64 = 32 * 1024 * 1024 * 1024;

fn configure_readonly_page_cache(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", READER_PAGE_CACHE_KIB)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    // Interactive readers map the store, up to READER_MMAP_SIZE_BYTES, and keep
    // the page cache above for pages the mapping does not serve. Mapping can
    // bypass pcache1's global LRU mutex when SQLite is built with
    // SQLITE_ENABLE_MEMORY_MANAGEMENT (BrokkAi/bifrost#21). Workspace builds
    // undefine that option through LIBSQLITE3_FLAGS in .cargo/config.toml, so
    // each page cache has a private reclamation group. Downstream Rust builds
    // do not inherit our Cargo configuration and must apply the build flags
    // themselves. Without SQLITE_MAX_MMAP_SIZE=68719476736LL, requests for
    // the larger derivation map silently clamp to SQLite's old ~2 GiB cap.
    //
    // Measured 2026-10-09 on Vector (2,796 files, 30.8 MB of source, 1.6 GB
    // store), whole-workspace cleartext-logging policy, one run per cell, host
    // load 17 to 118 from other work. Cold rows start from a fresh cache root,
    // warm rows reuse it. The 1 GiB row is a page cache of that size.
    //   cell             wall      user      sys    major faults  peak RSS
    //   8 MiB cold      4,656 s   2,180 s   2,182 s   420k       4.82 GB
    //   1 GiB cold      2,897 s   2,750 s     245 s   305k       5.05 GB
    //   2 GiB mmap cold 2,709 s   2,675 s     134 s   961k       6.00 GB
    //   8 MiB warm      4,688 s   1,971 s   2,309 s   320k       2.75 GB
    //   1 GiB warm      2,706 s   2,436 s     152 s   361k       3.52 GB
    //   2 GiB mmap warm 2,311 s   2,126 s      97 s   815k       4.42 GB
    // Against the 8 MiB cache, the mapping cut sys time by 94% (cold) and 96%
    // (warm) and wall time by 42% and 51%. Major faults rose 2.3x (cold) and
    // 2.5x (warm). Peak RSS counts shared file-backed pages, so it overstates
    // the private memory each reader holds. Proportional set size was not
    // measured. SQLite's default Linux mmap cap is 2,147,418,112 bytes;
    // Vector's 1.6 GB store fits, but large workspaces exceed it. Our build
    // raises the compiled cap to support the scoped derivation map above.
    //
    // Pool cost: every open reader keeps READER_PAGE_CACHE_KIB of private page
    // cache, so a 1 GiB cache would cost 1 GiB per pooled reader, up to 120 in
    // the MCP server. A mapping adds no private pages until a page is touched,
    // and touched pages are shared file-backed pages of one store file, which
    // the kernel can reclaim. The 1 GiB page cache also cut sys time in this
    // cell, so the mapping avoids private page-cache growth; each reader's
    // mapping still needs its own page tables.
    //
    // Latency, rust-mbx replay (2026-10-09, 10 repeats per case, three passes
    // per build, host load 17 to 150): definition and type p95 were lower with
    // the mapping in every pass, by 10 to 36 percent and 5 to 28 percent. The
    // heavy families (usages, call_relations, rename) moved with host load; in
    // the quietest pass each stayed within 6 percent of the master build.
    // Responses matched the master build after SegmentId values were
    // normalized.
    //
    // Contention, one MCP server with 32 and then 96 concurrent requests: p95
    // of admitted requests was within 6 percent of the master build. The server
    // runs 4 analyzer executions and queues 32, and refuses the rest with the
    // same error on both builds.
    conn.pragma_update(None, "mmap_size", READER_MMAP_SIZE_BYTES)
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
/// The source is only ever read. An older checkout keeps opening it, and the
/// existence of a newer file says nothing about whether the older one is still
/// live (issue #1589). Collection keeps at most one other versioned store next
/// to this build's: it may remove this source sooner when another candidate
/// has more recent use, and removes the retained alternate after it has gone
/// [`VERSION_STORE_GRACE_SECS`] unused. Renaming instead of copying would save
/// a transient doubling of one store's bytes and cost exactly the guarantee
/// #1589 was filed to establish.
///
/// The copy goes through SQLite's backup API rather than the filesystem
/// because a live source holds committed pages in its `-wal` sidecar; copying
/// the main file alone would silently drop them.
///
/// Only the holder of the cache directory's upgrade lock stages a copy. Each
/// copy is as large as the source store, and every linked worktree of a
/// repository shares one cache directory, so without the lock ten processes
/// starting at once each wrote their own 10 GB copy, and the ones that were
/// killed left those copies behind. A process that waited for the lock finds
/// the store the holder published and stages nothing.
///
/// The lock also guards *reading* the older stores. Selecting a candidate reads
/// its `user_version`, and SQLite's WAL locking protocol does not tolerate a
/// burst of concurrent openers on one store: an unlucky opener can spend the
/// protocol retry budget -- about ten seconds -- and then report
/// SQLITE_PROTOCOL. Every process starting while this build's store is missing
/// would otherwise probe the same older store at once (#5150).
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
    // Decide whether there is anything to import by name alone. Opening a
    // candidate here, before the lock, is what let a group of openers land on
    // one older store at the same time (#5150). A name this build cannot
    // import only costs one uncontended lock acquisition.
    if !has_importable_store_candidate(cache_dir)? {
        return Ok(());
    }
    // Held until this function returns, which is after the publish below.
    let upgrade_lock = open_upgrade_lock(cache_dir)?;
    match upgrade_lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            eprintln!(
                "Bifrost cache upgrade waiting for another process that is upgrading a store in {}",
                cache_dir.display()
            );
            upgrade_lock
                .lock()
                .map_err(|err| format!("cache DB I/O error locking upgrades: {err}"))?;
        }
        Err(std::fs::TryLockError::Error(err)) => {
            return Err(format!("cache DB I/O error locking upgrades: {err}"));
        }
    }
    if db_path.exists() {
        return Ok(());
    }
    // Free the space before this upgrade takes as much again.
    if let Err(error) = remove_abandoned_staged_copies(cache_dir) {
        eprintln!("Bifrost cache cleanup of interrupted upgrades skipped: {error}");
    }
    // The previous holder or a version-store sweep may have changed the
    // candidates while this process waited.
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

fn open_upgrade_lock(cache_dir: &Path) -> Result<std::fs::File> {
    let lock_path = cache_dir.join(UPGRADE_LOCK_FILE_NAME);
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| format!("cache DB I/O error opening {}: {err}", lock_path.display()))
}

/// Remove staged upgrade copies when no upgrade is running in `cache_dir`.
///
/// A busy lock means a live upgrade, which removes abandoned copies itself
/// before it stages; a later open retries otherwise.
fn collect_abandoned_staged_copies(cache_dir: &Path) -> Result<()> {
    // Most opens find nothing, and need not create the lock file to say so.
    if staged_copy_paths(cache_dir)?.is_empty() {
        return Ok(());
    }
    let upgrade_lock = open_upgrade_lock(cache_dir)?;
    match upgrade_lock.try_lock() {
        Ok(()) => remove_abandoned_staged_copies(cache_dir),
        Err(std::fs::TryLockError::WouldBlock) => Ok(()),
        Err(std::fs::TryLockError::Error(err)) => {
            Err(format!("cache DB I/O error locking upgrades: {err}"))
        }
    }
}

/// Remove every staged upgrade copy and sidecar in `cache_dir`.
///
/// The caller holds the upgrade lock. Every upgrade stages only while it holds
/// that lock, and the operating system releases it when the holder exits, so
/// each staged file left now belongs to a process that died mid-upgrade. The
/// lock rather than the file's age is the proof: a large upgrade writes for
/// minutes, and a suspended one for as long as it stays suspended.
fn remove_abandoned_staged_copies(cache_dir: &Path) -> Result<()> {
    let mut removed = Vec::new();
    let mut outcome = Ok(());
    for path in staged_copy_paths(cache_dir)? {
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                outcome = Err(format!(
                    "cache DB I/O error removing {}: {err}",
                    path.display()
                ));
                break;
            }
        }
    }
    if !removed.is_empty() {
        eprintln!("Bifrost cache removed copies left by interrupted upgrades: {removed:?}");
    }
    outcome
}

fn staged_copy_paths(cache_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))? {
        let entry = entry.map_err(|err| format!("cache DB I/O error: {err}"))?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(STAGED_UPGRADE_PREFIX.as_bytes())
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|err| format!("cache DB I/O error: {err}"))?;
        if !file_type.is_dir() {
            paths.push(entry.path());
        }
    }
    Ok(paths)
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
        .prefix(STAGED_UPGRADE_PREFIX)
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

/// Whether `cache_dir` holds any file whose name could be an older store.
///
/// A name-only decision, so it can run before the upgrade lock: the version a
/// candidate really declares needs its `user_version`, which is the lock
/// holder's job. The false positive -- a name in range that turns out to be
/// pre-native, unreadable, or already current -- costs one uncontended lock
/// acquisition, and the probe behind it rejects the file.
fn has_importable_store_candidate(cache_dir: &Path) -> Result<bool> {
    for entry in std::fs::read_dir(cache_dir).map_err(|err| format!("cache DB I/O error: {err}"))? {
        let entry = entry.map_err(|err| format!("cache DB I/O error: {err}"))?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new(LEGACY_CACHE_DB_FILE_NAME) {
            return Ok(true);
        }
        let importable_version =
            name.to_str()
                .and_then(store_file_version)
                .is_some_and(|version| {
                    (FIRST_NATIVE_CACHE_VERSION..CURRENT_MIGRATION_VERSION).contains(&version)
                });
        if importable_version {
            return Ok(true);
        }
    }
    Ok(false)
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
    if explicit_override.as_deref() == Some(db_path) {
        return None;
    }
    project_dir_for_cache(db_path)
}

fn project_dir_for_cache(db_path: &Path) -> Option<&Path> {
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

fn stage_legacy_project_cache_ignore(
    ignore_path: &Path,
    description: &str,
) -> Result<tempfile::NamedTempFile> {
    let parent = ignore_path.parent().ok_or_else(|| {
        format!(
            "legacy cache ignore has no parent directory: {}",
            ignore_path.display()
        )
    })?;
    let mut replacement = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to stage {description}: {err}"))?;
    replacement
        .write_all(GENERATED_LEGACY_PROJECT_GITIGNORE)
        .and_then(|()| sync_file(replacement.as_file()))
        .map_err(|err| format!("failed to stage {description}: {err}"))?;
    Ok(replacement)
}

fn create_legacy_project_cache_ignore(ignore_path: &Path) -> Result<()> {
    let replacement = stage_legacy_project_cache_ignore(ignore_path, "legacy cache ignore")?;
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
    let replacement =
        stage_legacy_project_cache_ignore(ignore_path, "narrowed legacy cache ignore")?;
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

fn is_whole_directory_gitignore_pattern(line: &str) -> bool {
    matches!(line, "*" | "/*" | "**" | "/**")
}

fn gitignore_ignores_entire_directory(content: &[u8]) -> bool {
    String::from_utf8_lossy(content)
        .lines()
        .any(|line| is_whole_directory_gitignore_pattern(line.trim()))
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
        ignores_all |= is_whole_directory_gitignore_pattern(line);
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
    // An explicit override skips legacy migration, but a reserved cache layout
    // still contains generated state that must never enter Git-backed scans.
    if project_dir_for_cache(&cache_dir.join(cache_db_file_name())).is_none() {
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
        .and_then(|()| sync_file(replacement.as_file()))
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
    register_seal_validation(conn)
        .map_err(|err| format!("cache DB seal validation registration error: {err}"))?;
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
    // -- see `drain_free_pages` for the mechanism (issue #2789).
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
    conn.pragma_update(None, "synchronous", sqlite_synchronous())
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
    conn.set_prepared_statement_cache_capacity(WRITER_PREPARED_STATEMENT_CACHE_CAPACITY);
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

pub fn set_wal_journal_mode(conn: &Connection) -> rusqlite::Result<String> {
    let current: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if current.eq_ignore_ascii_case("wal") {
        return Ok(current);
    }
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
}

fn ensure_wal_journal_mode(conn: &Connection) -> std::result::Result<(), InitializationPhaseError> {
    let updated = set_wal_journal_mode(conn)?;
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

    // Migration 140 replaces the semantic catalog to widen its import-kind
    // CHECK constraint. Disable FK actions around the migration transaction
    // so dropping the old parent does not cascade-delete its child rows;
    // migrate_locked runs foreign_key_check before commit, then enforcement is
    // restored before the migrated store is returned.
    if user_version < CURRENT_MIGRATION_VERSION {
        conn.pragma_update(None, "foreign_keys", "OFF")
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        let migration = migrate_locked(conn, false);
        let restore = conn
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|err| format!("cache DB SQLite error: {err}"));
        let outcome = match (migration, restore) {
            (Err(error), _) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(outcome), Ok(())) => outcome,
        };
        if matches!(outcome, LockedMigrationOutcome::Complete) {
            return drain_free_pages(conn);
        }
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

    if user_version == 0 && schema_objects.is_empty() {
        initialize_fresh_schema(&tx)?;
        tx.pragma_update(None, "user_version", CURRENT_MIGRATION_VERSION)
            .map_err(|err| format!("cache DB current-schema version error: {err}"))?;
        start_collection_cadence(&tx)?;
        user_version = CURRENT_MIGRATION_VERSION;
    } else if user_version == 0 {
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
fn start_collection_cadence(conn: &Connection) -> Result<()> {
    let updated = conn
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

/// This build's empty-store template. The digest covers what decides the
/// bytes of an empty store: the fresh schema and its seed rows, the schema
/// version, and the page size.
static STORE_TEMPLATE: Lazy<crate::sqlite_template::Template> = Lazy::new(|| {
    crate::sqlite_template::Template::new(
        "store",
        CURRENT_MIGRATION_VERSION,
        &[
            CURRENT_FRESH_SCHEMA_SQL.as_bytes(),
            &CACHE_PAGE_SIZE_BYTES.to_le_bytes(),
        ],
    )
});

/// Create a store that does not exist yet from [`STORE_TEMPLATE`]; see
/// [`crate::sqlite_template`]. A copied store still goes through [`migrate`],
/// whose schema identity check rejects a template that does not match this
/// build.
fn seed_new_store_from_template(db_path: &Path, template_dir: Option<&Path>) -> Result<bool> {
    crate::sqlite_template::seed_missing_database(
        db_path,
        template_dir,
        &STORE_TEMPLATE,
        build_fresh_store,
    )
}

/// Create an empty current-schema store at `path` through the ordinary path.
fn build_fresh_store(path: &Path) -> Result<()> {
    let mut conn = open_store_connection(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ConnectionRole::Writer,
    )
    .map_err(|err| format!("cache DB template SQLite error: {err}"))?;
    configure_connection(&mut conn)?;
    migrate(&mut conn)?;
    // Closing the only connection checkpoints the WAL into the main file and
    // removes the WAL, so the main file alone is the complete store.
    conn.close()
        .map_err(|(_, err)| format!("cache DB template close error: {err}"))
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
        let quoted = quote_sqlite_identifier(&name);
        tx.execute_batch(&format!("DROP {object_type} {quoted};"))
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    }
    tx.pragma_update(None, "user_version", 0)
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

pub(crate) fn quote_sqlite_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
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

fn initialize_fresh_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(CURRENT_FRESH_SCHEMA_SQL)
        .map_err(|err| format!("cache DB fresh-schema creation error: {err}"))
}

fn schema_object_definitions(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    raw_schema_object_definitions(conn).map(|definitions| {
        definitions
            .into_iter()
            .map(|(object_type, name, sql)| (object_type, name, normalize_schema_sql(&sql)))
            .collect()
    })
}

fn raw_schema_object_definitions(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
             ORDER BY type, name",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<(String, String, String)>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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
    use brokk_bifrost_test_macros::hardwon;
    // The EXPLAIN QUERY PLAN pins below run their assertions once against a
    // database with no planner statistics and once with the statistics
    // captured from real corpus stores, because production carries the latter
    // (issue #3016).
    use crate::cache_gc::PlannerStatisticsState;

    #[test]
    fn a_store_seeded_from_the_template_matches_a_store_opened_without_one() {
        let temp = tempfile::tempdir().unwrap();
        // The template builders open with SQLITE_OPEN_NOFOLLOW, which rejects a
        // symlink anywhere in the path, and production passes canonical paths.
        // macOS temp directories live under /var -> /private/var (#4604).
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let template_dir = root.join("templates");
        // The reference never touches a template: the ordinary open configures
        // and migrates the new file itself. It gets its own directory so that
        // the open's neighbour-store import and cleanup see nothing else.
        let reference = root.join("untemplated").join(cache_db_file_name());
        drop(open_unified_connection_with_template_dir(&reference, None).unwrap());

        // The first store builds and publishes the template; the second copies it.
        let first = root.join("first.db");
        let second = root.join("second.db");
        assert!(seed_new_store_from_template(&first, Some(&template_dir)).unwrap());
        assert!(seed_new_store_from_template(&second, Some(&template_dir)).unwrap());
        assert!(!seed_new_store_from_template(&second, Some(&template_dir)).unwrap());
        let template_entries = std::fs::read_dir(&template_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            template_entries,
            vec![STORE_TEMPLATE.file_name().to_owned()]
        );

        let describe = |path: &Path| {
            let conn = Connection::open(path).unwrap();
            let pragmas =
                ["page_size", "auto_vacuum", "journal_mode", "user_version"].map(|pragma| {
                    conn.query_row(&format!("PRAGMA {pragma}"), [], |row| {
                        row.get::<_, Value>(0)
                    })
                    .unwrap()
                });
            let tables = user_schema_objects(&conn)
                .unwrap()
                .into_iter()
                .filter(|(object_type, _)| object_type == "table")
                .map(|(_, name)| {
                    let rows: i64 = conn
                        .query_row(
                            &format!("SELECT COUNT(*) FROM {}", quote_sqlite_identifier(&name)),
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    (name, rows)
                })
                .collect::<Vec<_>>();
            (
                pragmas,
                schema_object_definitions_sha256(&conn).unwrap(),
                tables,
            )
        };
        let expected = describe(&reference);
        // Fixed values, so that a defect both paths share still fails: 32 KiB
        // pages, incremental auto-vacuum, WAL.
        assert_eq!(
            expected.0[..3],
            [
                Value::Integer(32 * 1024),
                Value::Integer(2),
                Value::Text("wal".to_owned())
            ]
        );
        assert_eq!(expected.1, CURRENT_SCHEMA_OBJECTS_SHA256);
        for seeded in [&first, &second] {
            assert_eq!(describe(seeded), expected, "{}", seeded.display());
            let mut conn = Connection::open(seeded).unwrap();
            migrate(&mut conn).unwrap();
            assert!(current_schema_is_valid(&conn).unwrap());
        }
    }

    #[test]
    fn residual_conversion_migration_preserves_gap_rows_and_bounds() {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 178)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 177).unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
            ["a".repeat(40)],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO semantic_ir_publications(blob_id, lang, producer_epoch,
             content_digest, source_bytes, outcome, procedure_count, logical_rows,
             payload_bytes, go_predeclared_builtins, publication_state)
             VALUES(?1, 'rust', 'fixture', zeroblob(32), 0, 0, 1, 1, 0, jsonb('[]'), 'complete')",
            [blob_id],
        )
        .unwrap();
        let insert = "INSERT INTO semantic_ir_gaps(blob_id, procedure, gap, point,
             subject, capability, impacts, kind, discharge, detail, source, evidence)
             VALUES(?1, 0, ?2, 0, 0, 12, 1, 1, ?3, 0, 0, 0)";
        conn.execute(insert, rusqlite::params![blob_id, 0, 12])
            .unwrap();
        assert!(
            conn.execute(insert, rusqlite::params![blob_id, 1, 13])
                .is_err()
        );
        conn.execute_batch(include_str!(
            "../migrations/cache/0178-semantic-ir-residual-conversion.sql"
        ))
        .unwrap();
        conn.execute(insert, rusqlite::params![blob_id, 1, 13])
            .unwrap();
        assert!(
            conn.execute(insert, rusqlite::params![blob_id, 2, 14])
                .is_err()
        );
        let rows = conn
            .prepare("SELECT gap, discharge FROM semantic_ir_gaps ORDER BY gap")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows, vec![(0, 12), (1, 13)]);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        conn.execute(
            "DELETE FROM semantic_ir_publications WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM semantic_ir_gaps", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    fn current_rust_connection() -> Connection {
        let mut connection = Connection::open_in_memory().expect("open in-memory cache DB");
        configure_connection(&mut connection).expect("configure cache DB");
        migrate(&mut connection).expect("migrate cache DB");
        connection
    }

    fn seal_rust_source_manifest(conn: &Connection, blob_id: i64) -> rusqlite::Result<usize> {
        conn.execute(
            "UPDATE source_fact_manifests
                SET publication_state = 'complete'
              WHERE blob_id = ?1",
            [blob_id],
        )
    }

    #[cfg(unix)]
    fn assert_elevated_permission_advice(error: &str, path: &Path) {
        assert!(
            error.contains(&path.display().to_string())
                && error.contains("elevated filesystem permissions"),
            "{error}"
        );
    }

    /// Whether this process's own writes are constrained by the target
    /// directory's mode bits, probed exactly as [`cache_write_denial`] probes a
    /// denial. uid 0 and processes holding CAP_DAC_OVERRIDE bypass the 0o555
    /// injection the permission tests use, so the denial cannot be injected for
    /// them and those tests are not applicable (issue #5090).
    #[cfg(unix)]
    fn mode_bits_deny_writes(directory: &Path) -> bool {
        tempfile::NamedTempFile::new_in(directory).is_err()
    }

    #[path = "cpp_class_templates.rs"]
    mod cpp_class_templates;
    #[path = "csharp_compilation_migration.rs"]
    mod csharp_compilation_migration;
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
        populate_store_with_free_pages(&conn);
        conn
    }

    fn populate_store_with_free_pages(conn: &Connection) -> i64 {
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
        free
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

            let free = populate_store_with_free_pages(&conn);

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
    #[hardwon(
        "52536713ff40: shutdown checkpoint contention must defer only truncation and restore the busy timeout"
    )]
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

    /// A store this build imports: the pre-versioning file, at this schema.
    fn create_importable_store(cache_dir: &Path) {
        let legacy = cache_dir.join(LEGACY_CACHE_DB_FILE_NAME);
        std::fs::File::create(&legacy).unwrap();
        build_fresh_store(&legacy).unwrap();
    }

    /// The files a process killed mid-upgrade leaves: the staged copy and its
    /// SQLite sidecars.
    fn leave_interrupted_upgrade(cache_dir: &Path, stem: &str) -> Vec<PathBuf> {
        STORE_FILE_SUFFIXES
            .iter()
            .map(|suffix| {
                let path = cache_dir.join(format!("{STAGED_UPGRADE_PREFIX}{stem}{suffix}"));
                std::fs::write(&path, b"interrupted upgrade").unwrap();
                path
            })
            .collect()
    }

    #[test]
    #[hardwon(
        "473825ed9b2c: concurrent openers each staged a full copy of the store for one upgrade"
    )]
    fn concurrent_upgrades_stage_one_copy_and_publish_one_store() {
        const UPGRADERS: usize = 8;

        let temp = tempfile::tempdir().unwrap();
        // Staging opens with SQLITE_OPEN_NOFOLLOW (#4604).
        let root = std::fs::canonicalize(temp.path()).unwrap();
        create_importable_store(&root);
        let db_path = root.join(cache_db_file_name());
        let barrier = Barrier::new(UPGRADERS);
        let finished = std::sync::atomic::AtomicBool::new(false);

        // The threads call the import directly. `open_unified_connection`
        // already serializes openers of one path inside a process, so only the
        // upgrade lock stands between processes. That lock belongs to each
        // open file, not to the process, so threads contend for it the same
        // way processes do.
        let (results, staged_names) = thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                let mut staged_names = HashSet::new();
                while !finished.load(std::sync::atomic::Ordering::SeqCst) {
                    for entry in std::fs::read_dir(&root).unwrap().flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with(STAGED_UPGRADE_PREFIX)
                            && !STORE_FILE_SUFFIXES[1..]
                                .iter()
                                .any(|suffix| name.ends_with(suffix))
                        {
                            staged_names.insert(name);
                        }
                    }
                }
                staged_names
            });
            let upgraders = (0..UPGRADERS)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        import_newest_older_store(&db_path)
                    })
                })
                .collect::<Vec<_>>();
            let results = upgraders
                .into_iter()
                .map(|handle| handle.join().expect("upgrade thread panicked"))
                .collect::<Vec<_>>();
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            (results, watcher.join().expect("watcher thread panicked"))
        });

        assert!(
            results.iter().all(Result::is_ok),
            "concurrent upgrades failed: {results:#?}"
        );
        // The first holder publishes; every waiter then finds the store and
        // stages nothing. The watcher can miss the one copy, never add one.
        assert!(
            staged_names.len() <= 1,
            "more than one upgrade staged a copy: {staged_names:?}"
        );
        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(staged_copy_paths(&root).unwrap().is_empty());
    }

    #[test]
    #[hardwon(
        "473825ed9b2c: copies staged by killed upgrades were never removed and filled the disk"
    )]
    fn opening_removes_interrupted_upgrade_copies_and_nothing_else() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        create_importable_store(&root);
        let mut interrupted = leave_interrupted_upgrade(&root, "Ab12Cd");
        interrupted.extend(leave_interrupted_upgrade(&root, "Ef34Gh"));
        std::fs::create_dir(root.join("semantic-packs")).unwrap();
        let bystanders: Vec<(PathBuf, String)> = [
            ".gitignore",
            "bifrost_cache.v150.db",
            "bifrost_cache.v150.db-wal",
            "bifrost_cache.db.schema14.bak",
            "catalog.db",
            "catalog.db-wal",
            "semantic-packs/catalog.db",
            "bifrost_cache.v150.db.initial-build.lock",
            &format!("{}{INITIAL_BUILD_LOCK_SUFFIX}", cache_db_file_name()),
        ]
        .iter()
        .map(|name| {
            let path = root.join(name);
            let expected_contents = format!("bystander {name}");
            std::fs::write(&path, &expected_contents).unwrap();
            (path, expected_contents)
        })
        .collect();
        let legacy = root.join(LEGACY_CACHE_DB_FILE_NAME);
        let legacy_before = std::fs::read(&legacy).unwrap();

        let conn = open_unified_connection(&root.join(cache_db_file_name())).unwrap();

        assert!(current_schema_is_valid(&conn).unwrap());
        let left: Vec<&PathBuf> = interrupted.iter().filter(|path| path.exists()).collect();
        assert!(
            left.is_empty(),
            "interrupted upgrade files survived: {left:?}"
        );
        for (path, expected_contents) in &bystanders {
            let name = path.strip_prefix(&root).unwrap().display();
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                *expected_contents,
                "cleanup touched {name}"
            );
        }
        assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
    }

    #[test]
    fn opening_leaves_the_copy_of_a_live_upgrade_alone() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let live = leave_interrupted_upgrade(&root, "Ij56Kl");
        // A live upgrade holds the lock until it publishes.
        let upgrade_lock = open_upgrade_lock(&root).unwrap();
        upgrade_lock.lock().unwrap();

        let conn = open_unified_connection(&root.join(cache_db_file_name())).unwrap();

        assert!(current_schema_is_valid(&conn).unwrap());
        let gone: Vec<&PathBuf> = live.iter().filter(|path| !path.exists()).collect();
        assert!(gone.is_empty(), "removed files of a live upgrade: {gone:?}");
        upgrade_lock.unlock().unwrap();
    }

    #[test]
    #[hardwon(
        "#5150: the upgrade probe opened the older store before the upgrade lock, so eight Windows openers read one WAL store at once"
    )]
    fn upgrade_probe_opens_no_older_store_before_the_lock() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        // The legacy candidate is the one the probe opens to read its
        // `user_version`, and SQLite cannot read these contents. A probe that
        // runs before the lock therefore fails here while the lock is held.
        std::fs::write(root.join(LEGACY_CACHE_DB_FILE_NAME), b"not a database").unwrap();
        let db_path = root.join(cache_db_file_name());
        let (probed, probes) = std::sync::mpsc::channel();
        let holder = open_upgrade_lock(&root).unwrap();
        holder.lock().unwrap();

        let importer = thread::spawn(move || {
            let outcome = import_newest_older_store(&db_path);
            let _ = probed.send(());
            outcome
        });

        assert!(
            probes.recv_timeout(Duration::from_millis(500)).is_err(),
            "the importer finished while another process held the upgrade lock"
        );
        holder.unlock().unwrap();
        // Holding the lock, it reaches the candidate and reports the probe
        // failure.
        let error = importer
            .join()
            .expect("importer thread panicked")
            .unwrap_err();
        assert!(error.contains("SQLite error"), "{error}");
    }

    #[test]
    fn persistent_writer_registers_seal_validation() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_unified_connection(&dir.path().join("seal.db")).unwrap();
        conn.execute_batch(
            "INSERT INTO blobs(id, blob_oid, lang, generation)
               VALUES(64, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'go', 0);
             INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest,
               expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(64, 'go', 'go', 'seal-test', zeroblob(32), 0, 1, 0, 'building');",
        )
        .unwrap();
        assert_eq!(
            conn.execute(
                "UPDATE resolution_fragment_interiors SET publication_state = 'complete'
                 WHERE blob_id = 64",
                [],
            )
            .unwrap(),
            1,
        );
        let validates: bool = conn
            .query_row("SELECT bifrost_seal_validates(1)", [], |row| row.get(0))
            .unwrap();
        assert!(validates, "test builds validate even unsampled blobs");
        // A raw connection must fail loudly, including for an empty UPDATE.
        let raw = Connection::open(dir.path().join("seal.db")).unwrap();
        let error = raw
            .execute(
                "UPDATE resolution_fragment_interiors SET publication_state = 'complete'
             WHERE blob_id = 65",
                [],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no such function: bifrost_seal_validates"),
            "{error}"
        );
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
    #[hardwon("#5664: Go summary retirement left members and containers orphaned during upgrades")]
    fn go_domain_migration_withdraws_v1_contexts_and_summary_rows() {
        // #6291: later compatible migrations must not move this regression's
        // starting schema past 0206 or replace the Go upgrade it exercises.
        let go_domain_migration = POST_BASELINE_MIGRATIONS
            .iter()
            .find(|migration| migration.version == 206)
            .expect("Go domain migration remains in the compatible chain");
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < go_domain_migration.version)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute_batch("INSERT INTO workspace_revisions VALUES(printf('%064d',0),'go',0,1);
          INSERT INTO go_context_selections VALUES(1,printf('%064d',0),'go',0,1,zeroblob(32),1);
          INSERT INTO go_context_publications VALUES(1,1,zeroblob(32),0,jsonb('[]'));
          INSERT INTO go_context_heads VALUES(1,1);
          INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key)
            VALUES(1,'example.test/root','root','','',zeroblob(32),0,jsonb('[]'),randomblob(32));
          INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,publication_state)
            VALUES(1,'go','go_package',randomblob(32),randomblob(32),'test',1,0,'building');
          INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,profile_digest)
            VALUES(printf('%064d',0),'go',0,randomblob(32),1,1,zeroblob(32));").unwrap();
        conn.execute_batch("INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(1,printf('%040d',1),'go',0);
          INSERT INTO resolution_unit_summary_members VALUES(1,0,1,'main.go','source');
          INSERT INTO resolution_unit_summary_containers VALUES(1,'',NULL);
          INSERT INTO resolution_unit_summary_placements VALUES(1,'',0,0);
          INSERT INTO resolution_unit_summary_dependencies VALUES(1,0,zeroblob(32),zeroblob(32),'external',NULL);
          INSERT INTO resolution_unit_summary_dependency_names VALUES(1,'normal','dep',0);
          INSERT INTO resolution_unit_summary_imports VALUES(1,1,0,'named',0,0,'resolved');
          INSERT INTO resolution_unit_summary_reads VALUES(1,0,'epoch',zeroblob(32),zeroblob(32));
          INSERT INTO resolution_unit_summary_gaps VALUES(1,'test','',jsonb('{}'));").unwrap();
        validate_foreign_keys(&conn).unwrap();
        // Match migrate(): historical DDL cannot rely on cascading FK actions.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute_batch(go_domain_migration.sql).unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for table in [
            "go_context_selections",
            "go_context_publications",
            "go_package_instances",
            "go_package_files",
            "go_package_imports",
            "go_context_domain_modules",
            "resolution_unit_summary_versions",
            "resolution_unit_summaries",
            "resolution_unit_summary_members",
            "resolution_unit_summary_containers",
            "resolution_unit_summary_placements",
            "resolution_unit_summary_dependencies",
            "resolution_unit_summary_dependency_names",
            "resolution_unit_summary_imports",
            "resolution_unit_summary_reads",
            "resolution_unit_summary_gaps",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "migration must withdraw v1 {table}");
        }
        validate_foreign_keys(&conn).unwrap();
    }

    #[test]
    fn shared_summary_placement_migration_and_foreign_keys() {
        let mut conn = create_current_baseline_without_migration();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 190)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        let header = "INSERT INTO resolution_unit_summaries(summary_id, lang, unit_kind, unit_key, summary_digest, producer_epoch, derivation_version, complete, publication_state) VALUES(?1,?2,?3,zeroblob(32),?4,'test',1,0,'building')";
        conn.execute(
            header,
            rusqlite::params![1, "go", "go_package", [1u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            header,
            rusqlite::params![2, "rust", "rust_crate", [2u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'rust',0)",
            [seeded_oid("shared-summary-member")],
        )
        .unwrap();
        let blob = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO resolution_unit_summary_members VALUES(2,0,?1,'src/lib.rs','declared')",
            [blob],
        )
        .unwrap();
        conn.execute_batch("INSERT INTO rust_resolution_unit_summary_containers VALUES(2,'crate','module','root');
            INSERT INTO rust_resolution_unit_summary_placements VALUES(2,'crate',0,'declared',0,NULL,NULL);
            INSERT INTO rust_resolution_unit_summary_root_routes(summary_id,member_ordinal,module_path,route_key,reference_source_site,target_unit_key,target_module_path,target_name) VALUES(2,0,'crate',1,1,zeroblob(32),'crate','Item');").unwrap();
        conn.pragma_update(
            None,
            "user_version",
            POST_BASELINE_MIGRATIONS
                .iter()
                .rfind(|migration| migration.version < 190)
                .unwrap()
                .version,
        )
        .unwrap();
        // Preserve the Go row through the placement migration and its successors.
        // Migration 0206 deliberately withdraws the old Go summary family.
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| (190..206).contains(&migration.version))
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 205).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT group_concat(lang) FROM resolution_unit_summaries",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "go"
        );
        for old in [
            "rust_resolution_unit_summary_containers",
            "rust_resolution_unit_summary_placements",
            "rust_resolution_unit_summary_dependency_names",
        ] {
            assert!(
                !conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1)",
                        [old],
                        |row| row.get::<_, bool>(0)
                    )
                    .unwrap()
            );
        }
        conn.execute(
            header,
            rusqlite::params![2, "rust", "rust_crate", [2u8; 32].as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_unit_summary_members VALUES(2,0,?1,'src/lib.rs','declared')",
            [blob],
        )
        .unwrap();
        conn.execute_batch("INSERT INTO resolution_unit_summary_containers VALUES(2,'',NULL);
            INSERT INTO resolution_unit_summary_placements VALUES(2,'',0,0);
            INSERT INTO rust_resolution_unit_summary_container_attributes(summary_id,container_path,kind) VALUES(2,'','module');
            INSERT INTO rust_resolution_unit_summary_placement_attributes(summary_id,container_path,member_ordinal,placement,source_kind) VALUES(2,'',0,'root','declared');
            INSERT INTO resolution_unit_summary_dependencies VALUES(2,0,zeroblob(32),zeroblob(32),'external',NULL);
            INSERT INTO rust_resolution_unit_summary_root_routes(summary_id,member_ordinal,module_path,route_key,reference_source_site,target_unit_key,target_module_path,target_name) VALUES(2,0,'crate',1,1,zeroblob(32),'crate','Item');
            INSERT INTO resolution_unit_summary_dependency_names VALUES(2,'normal','first',0),(2,'normal','alias',0),(2,'dev','first',NULL);").unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT module_path FROM rust_unit_summary_containers WHERE summary_id=2",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "crate"
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_unit_summary_placements VALUES(2,'missing',0,0)",
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_unit_summary_placements VALUES(2,'',1,0)",
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_unit_summary_containers VALUES(2,'child',NULL)",
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_unit_summary_dependency_names VALUES(2,'normal','first',1)",
                []
            )
            .is_err()
        );
        conn.execute(
            "DELETE FROM resolution_unit_summary_containers WHERE summary_id=2",
            [],
        )
        .unwrap();
        for table in [
            "resolution_unit_summary_placements",
            "rust_resolution_unit_summary_container_attributes",
            "rust_resolution_unit_summary_placement_attributes",
            "rust_resolution_unit_summary_root_routes",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        conn.execute(
            "DELETE FROM resolution_unit_summaries WHERE summary_id=2",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summary_dependency_names",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        validate_foreign_keys(&conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summaries WHERE lang='go'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        validate_foreign_keys(&conn).unwrap();
    }

    #[test]
    fn executable_scope_owner_migration_preserves_children_and_scope_kinds() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 180)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute(
            "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'rust',0)",
            [seeded_oid("executable-scope-migration")],
        )
        .unwrap();
        let blob = conn.last_insert_rowid();
        conn.execute("INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state) VALUES(?1,'rust','rust','test',zeroblob(32),0,1,0,'building')", [blob]).unwrap();
        conn.execute(
            "INSERT INTO resolution_member_scope_properties VALUES(?1,1,10)",
            [blob],
        )
        .unwrap();
        conn.execute("INSERT INTO resolution_member_owner_properties(blob_id,definition_semantic_key,owner_definition_semantic_key,owner_scope_head_node_key,member_kind,member_access,qualifier_compatibility) VALUES(?1,2,1,10,'method','instance','runtime_only')", [blob]).unwrap();
        conn.pragma_update(None, "user_version", 179).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT scope_kind FROM resolution_member_scope_properties WHERE blob_id=?1",
                [blob],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "type_body"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_member_owner_properties WHERE blob_id=?1",
                [blob],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        conn.execute("INSERT INTO resolution_member_scope_properties VALUES(?1,2,11,'executable'),(?1,2,12,'executable')", [blob]).unwrap();
        assert!(
            conn.execute(
                "INSERT INTO resolution_member_scope_properties VALUES(?1,1,13,'type_body')",
                [blob]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_member_scope_properties VALUES(?1,3,11,'executable')",
                [blob]
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_member_scope_properties VALUES(?1,3,14,'block')",
                [blob]
            )
            .is_err()
        );
        validate_foreign_keys(&conn).unwrap();
        conn.execute("DELETE FROM blobs WHERE id=?1", [blob])
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_member_scope_properties",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_member_owner_properties",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5141: semantic language was incorrectly constrained to the owner blob dialect"
    )]
    fn class_set_storage_identity_migration_preserves_owned_rows_and_constraints() {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 193)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 192).unwrap();
        let blob_id = insert_visibility_blob_fixture(&conn, "class-set-owner-migration", None, 1);
        conn.execute_batch(&format!(
            "INSERT INTO class_set_root_result_generations VALUES(
               41, 'java', zeroblob(32), zeroblob(32), zeroblob(32),
               zeroblob(32), zeroblob(32), 1, 0);
             INSERT INTO class_set_finding_free_root_results VALUES(
               42, 41, zeroblob(32), 'Owner.java', {blob_id}, 'java',
               'complete', 0, 1, 17, zeroblob(32), 0);
             INSERT INTO class_set_finding_free_root_rows(
               result_id, row_ordinal, rel_path, start_byte, start_line,
               start_byte_column, end_byte, end_line, end_byte_column,
               member, atom_kind, class_name, class_set_status
             ) VALUES(42, 0, 'Owner.java', 0, 0, 0, 1, 0, 1,
                      'member', 'workspace', 'Owner', 'known');
             INSERT INTO class_set_procedure_surfaces(
               surface_id, surface_digest, procedure_lineage, owner_rel_path,
               owner_blob_id, lang, artifact_public_identity, artifact_content_identity,
               schema_version, local_structure_digest, behavior_read_digest,
               carrier_semantics_digest, direct_calls_digest, call_count, binding_count,
               entered_count, lexical_child_count, read_count, completion, published_at,
               exact_behavior_digest, exact_provenance_digest
             ) VALUES(43, zeroblob(32), zeroblob(32), 'Owner.java', {blob_id}, 'java',
                      zeroblob(32), zeroblob(32), 1, zeroblob(32), zeroblob(32),
                      zeroblob(32), zeroblob(32), 0, 0, 0, 1, 0, 'complete', 0,
                      zeroblob(32), zeroblob(32));
             INSERT INTO class_set_procedure_surface_lexical_children VALUES(
               43, 0, zeroblob(32), 'Owner.java', 'java',
               zeroblob(32), zeroblob(32), zeroblob(32));
             INSERT INTO class_set_summaries(
               summary_id, lookup_digest, procedure_lineage, owner_rel_path, owner_blob_id,
               lang, artifact_public_identity, artifact_content_identity, schema_version,
               semantics_digest, context_digest, behavior_read_digest, dependency_digest,
               carrier_digest, field_slots_digest, entry_fact_ordinal, fact_count,
               exit_count, reached_count, dependency_count, read_count, charge_count,
               completion, budget_mode, output_digest, content_digest, published_at,
               root_surface_digest, direct_calls_digest
             ) VALUES(44, zeroblob(32), zeroblob(32), 'Owner.java', {blob_id}, 'java',
                      zeroblob(32), zeroblob(32), 1, zeroblob(32), zeroblob(32),
                      zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(32),
                      0, 1, 1, 0, 0, 0, 1, 'complete', 'exhaustive',
                      zeroblob(32), zeroblob(32), 0, zeroblob(32), zeroblob(32));
             INSERT INTO class_set_summary_charges VALUES(44, 'fact', 1);"
        ))
        .unwrap();

        // Migration 211 discards every class-set summary and surface, so the
        // rows this test follows stop at the chain before it. As in `migrate`,
        // a rebuilt parent must not cascade into its children.
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| (193..211).contains(&migration.version))
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        for (table, key, id) in [
            ("class_set_finding_free_root_results", "result_id", 42),
            ("class_set_procedure_surfaces", "surface_id", 43),
            ("class_set_summaries", "summary_id", 44),
        ] {
            let owner: (i64, String) = conn
                .query_row(
                    &format!("SELECT owner_blob_id, lang FROM {table} WHERE {key} = ?1"),
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(owner, (blob_id, "java".into()));
        }
        assert_eq!(
            conn.query_row(
                "SELECT payload_text_bytes FROM class_set_finding_free_root_results WHERE result_id = 42",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            21
        );
        for table in [
            "class_set_finding_free_root_rows",
            "class_set_procedure_surface_lexical_children",
            "class_set_summary_charges",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
                1
            );
        }
        assert!(
            conn.execute(
                "UPDATE class_set_summaries SET root_surface_digest = NULL",
                []
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "UPDATE class_set_summaries SET direct_calls_digest = NULL",
                []
            )
            .is_err()
        );

        // A dialect-specific physical owner must coexist with a coarse semantic
        // language. The root generation still enforces its semantic language.
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'typescript:ts', 0)",
            [seeded_oid("class-set-typescript-owner")],
        )
        .unwrap();
        let ts_blob_id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE class_set_procedure_surfaces SET owner_blob_id = ?1, lang = 'typescript'",
            [ts_blob_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE class_set_summaries SET owner_blob_id = ?1, lang = 'typescript'",
            [ts_blob_id],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE class_set_finding_free_root_results SET owner_blob_id = ?1, lang = 'typescript'",
                [ts_blob_id],
            )
            .is_err());
        conn.execute(
            "UPDATE class_set_root_result_generations SET lang = 'typescript'",
            [],
        )
        .expect_err("a live result must keep its generation language");
        conn.execute_batch(
            "DELETE FROM class_set_finding_free_root_results;
             UPDATE class_set_root_result_generations SET lang = 'typescript';",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO class_set_finding_free_root_results VALUES(
               42, 41, zeroblob(32), 'subject.ts', ?1, 'typescript',
               'complete', 0, 0, 13, zeroblob(32), 0)",
            [ts_blob_id],
        )
        .unwrap();
        validate_foreign_keys(&conn).unwrap();
        conn.execute("DELETE FROM blobs WHERE id = ?1", [ts_blob_id])
            .unwrap();
        for table in [
            "class_set_finding_free_root_results",
            "class_set_finding_free_root_rows",
            "class_set_procedure_surfaces",
            "class_set_procedure_surface_lexical_children",
            "class_set_summaries",
            "class_set_summary_charges",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
                0
            );
        }
        validate_foreign_keys(&conn).unwrap();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version >= 211)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn python_environment_migration_preserves_existing_summary_family() {
        let mut conn = create_current_baseline_without_migration();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 196) {
            conn.execute_batch(migration.sql).unwrap();
        }
        for (id, lang, kind, path, profile) in [
            (71, "rust", "rust_crate", "src/lib.rs", [0u8; 32]),
            (93, "go", "go_package", "main.go", [9u8; 32]),
        ] {
            conn.execute(
                "INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(?1,?2,?3,0)",
                rusqlite::params![id, seeded_oid(lang), lang],
            )
            .unwrap();
            conn.execute("INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,member_count,output_digest,publication_state) VALUES(?1,?2,?3,?4,?4,'preserved',3,1,1,?4,'complete')",
                rusqlite::params![id,lang,kind,[id as u8;32].as_slice()]).unwrap();
            conn.execute(
                "INSERT INTO resolution_unit_summary_members VALUES(?1,0,?1,?2,'source')",
                rusqlite::params![id, path],
            )
            .unwrap();
            conn.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,profile_digest,valid_from,valid_until,summary_id) VALUES(?1,?2,4,?3,?4,7,NULL,?5)",
                rusqlite::params!["w".repeat(64),lang,[id as u8;32].as_slice(),profile.as_slice(),id]).unwrap();
            conn.execute(
                "INSERT INTO resolution_unit_summary_containers VALUES(?1,'',NULL)",
                [id],
            )
            .unwrap();
        }
        // Exercise the transitive FK to versions, a generated column, and rowid tables.
        conn.execute_batch("INSERT INTO rust_crate_topologies VALUES(17,zeroblob(32),zeroblob(32),'preserved','lib','example','2021','std',jsonb('[]'),1,zeroblob(32),'complete');
            INSERT INTO rust_resolution_unit_summary_contexts VALUES(71,'lib','example','2021','std',jsonb('[]'),1,0);
            INSERT INTO rust_resolution_unit_summary_container_attributes(summary_id,container_path,kind) VALUES(71,'','module');
            INSERT INTO rust_resolution_unit_summary_binding_completeness VALUES(71,0,1,'complete','');").unwrap();
        conn.execute("INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id) VALUES(?1,'rust',4,?2,7,71,17)",
            rusqlite::params!["w".repeat(64),[71u8;32].as_slice()]).unwrap();
        validate_foreign_keys(&conn).unwrap();
        // Compare every old relation, including generated values and implicit rowids.
        let tables = conn.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
            .query_map([], |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?))).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let read = |connection: &Connection, name: &str, definition: &str| {
            let fields = if definition.contains("WITHOUT ROWID") {
                "*"
            } else {
                "rowid,*"
            };
            let mut statement = connection
                .prepare(&format!("SELECT {fields} FROM {name} ORDER BY 1,2"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let before: Vec<_> = tables
            .iter()
            .map(|(name, sql)| read(&conn, name, sql))
            .collect();
        let indexes = conn.prepare("SELECT name,sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name").unwrap()
            .query_map([], |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?))).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        conn.pragma_update(None, "user_version", 195).unwrap();
        conn.execute_batch("SAVEPOINT python_environment_preservation")
            .unwrap();
        // Check preservation at the Python environment migration boundary.
        // Later migration 0206 deliberately retires the Go rows seeded above.
        let migration = POST_BASELINE_MIGRATIONS
            .iter()
            .find(|m| m.version == 196)
            .unwrap();
        conn.execute_batch(migration.sql).unwrap();
        for ((name, sql), expected) in tables.iter().zip(before) {
            assert_eq!(
                read(&conn, name, sql),
                expected,
                "changed rows or ids in {name}"
            );
        }
        for (name, expected) in indexes {
            let actual: String = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                    [&name],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(actual, expected, "changed index {name}");
        }
        validate_foreign_keys(&conn).unwrap();
        // Restore the 0195 fixture so the production upgrader also exercises
        // the entire populated-store path through 0206 in its own transaction.
        conn.execute_batch(
            "ROLLBACK TO python_environment_preservation; RELEASE python_environment_preservation",
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summaries WHERE lang='go'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summary_members WHERE summary_id=71",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        validate_foreign_keys(&conn).unwrap();
        assert!(current_schema_is_valid(&conn).unwrap());
        // Exactly the approved new kind and profile authority are admitted.
        conn.execute("INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,publication_state) VALUES(101,'python','python_environment',zeroblob(32),?1,'native',1,0,'building')", [[101u8;32].as_slice()]).unwrap();
        conn.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,profile_digest,valid_from,summary_id) VALUES(?1,'python',4,zeroblob(32),?2,7,101)",rusqlite::params!["w".repeat(64),[5u8;32].as_slice()]).unwrap();
        for lang in ["rust", "java", "kotlin", "scala"] {
            assert!(conn.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,profile_digest,valid_from,summary_id) VALUES(?1,?2,4,zeroblob(32),?3,7,101)",rusqlite::params!["w".repeat(64),lang,[5u8;32].as_slice()]).is_err());
        }
        validate_foreign_keys(&conn).unwrap();
    }

    #[test]
    fn csharp_compilation_metadata_migration_withdraws_old_sets_and_selections() {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 217)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO workspace_revisions(workspace_id,lang,generation,revision)
             VALUES(printf('%064d',0),'csharp',1,1);
             INSERT INTO csharp_compilation_sets(set_id,workspace_id,lang,generation,
                 derivation_version,input_digest,output_digest,membership_complete,gaps)
             VALUES(1,printf('%064d',0),'csharp',1,1,zeroblob(32),zeroblob(32),1,jsonb('[]'));
             INSERT INTO csharp_compilations(compilation_id,set_id,project_path,references_complete,transitive_flow)
             VALUES(1,1,'App.csproj',1,1),(2,1,'Lib.csproj',1,1);
             INSERT INTO csharp_compilation_items(compilation_id,ordinal,set_id,kind,rel_path)
             VALUES(1,0,1,'include','App.cs');
             INSERT INTO csharp_project_references(from_compilation_id,target_compilation_id) VALUES(1,2);
             INSERT INTO csharp_compilation_selections(workspace_id,lang,generation,revision,set_id)
             VALUES(printf('%064d',0),'csharp',1,1,1);"
        ).unwrap();
        conn.execute_batch(
            POST_BASELINE_MIGRATIONS
                .iter()
                .find(|migration| migration.version == 217)
                .unwrap()
                .sql,
        )
        .unwrap();
        for table in [
            "csharp_compilation_sets",
            "csharp_compilations",
            "csharp_compilation_items",
            "csharp_project_references",
            "csharp_compilation_selections",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "withdraw v1 relation {table}");
        }
        validate_foreign_keys(&conn).unwrap();
        // The assertions above isolate migration 217. The current-schema check
        // also needs every migration added after it.
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version > 217)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        assert!(current_schema_shape_is_valid(&conn).unwrap());
    }

    #[test]
    fn unresolved_impl_declaration_migration_rebuilds_and_constrains_resolved_halves() {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 216) {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute(
            "INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(1,?1,'rust',0)",
            [seeded_oid("unresolved-impl-declaration-migration")],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state)
             VALUES(1,'rust','rust','test',zeroblob(32),0,1,0,'building');
             INSERT INTO rust_crate_topologies VALUES(1,zeroblob(32),zeroblob(32),'test','lib','example','2021','std',jsonb('[]'),1,zeroblob(32),'complete');
             INSERT INTO rust_crate_unresolved_trait_impls VALUES(1,'subject','Alias',1,1,'src/lib.rs',NULL,'resolved','crate');",
        )
        .unwrap();
        conn.execute_batch(
            POST_BASELINE_MIGRATIONS
                .iter()
                .find(|m| m.version == 216)
                .unwrap()
                .sql,
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_unresolved_trait_impls",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0,
            "legacy halves lack declaration identities and must be re-derived"
        );
        let mut insert = conn.prepare(
            "INSERT INTO rust_crate_unresolved_trait_impls VALUES(1,'subject','Alias',1,1,'src/lib.rs',NULL,?1,'crate',?2,?3,?4,'crate')",
        ).unwrap();
        for (reason, blob, site, path) in [
            ("resolved", None, None, None),
            ("resolved", Some(1), None, Some("src/lib.rs")),
            ("resolved", Some(1), Some(1), None),
            ("unbound", Some(1), Some(1), Some("src/lib.rs")),
            ("unbound", None, Some(1), None),
            ("bound_without_declaration", None, None, Some("src/lib.rs")),
            ("resolved", Some(1), Some(-1), Some("src/lib.rs")),
            (
                "resolved",
                Some(1),
                Some(4_294_967_296_i64),
                Some("src/lib.rs"),
            ),
            ("resolved", Some(1), Some(1), Some("")),
        ] {
            let error = insert
                .execute(rusqlite::params![reason, blob, site, path])
                .unwrap_err();
            assert!(
                error.to_string().contains("CHECK constraint failed"),
                "{reason:?}, {blob:?}, {site:?}, {path:?}: {error}"
            );
        }
        let error = insert
            .execute(rusqlite::params!["resolved", 2, 1, "src/lib.rs"])
            .unwrap_err();
        assert!(
            error.to_string().contains("FOREIGN KEY constraint failed"),
            "{error}"
        );
        insert
            .execute(rusqlite::params![
                "resolved",
                1,
                4_294_967_295_i64,
                "src/lib.rs"
            ])
            .unwrap();
        insert
            .execute(rusqlite::params![
                "unbound",
                None::<i64>,
                None::<i64>,
                None::<&str>
            ])
            .unwrap();
        validate_foreign_keys(&conn).unwrap();
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
    #[brokk_bifrost_test_macros::hardwon(
        "#6214: existing JVM package visibility labels must migrate to the reader's canonical label"
    )]
    fn jvm_package_private_visibility_migration_rewrites_legacy_label() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version <= 196) {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute(
            "INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES('provider','example.Owner',1,1,1,1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,parameters_jsonb) VALUES('provider','example.Owner',0,'ordinary','method','package',0,0,0,jsonb('[]'))",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 196).unwrap();
        migrate(&mut conn).unwrap();
        let visibility: String = conn
            .query_row(
                "SELECT visibility FROM jvm_external_owner_members WHERE provider_id='provider' AND owner_fqn='example.Owner' AND ordinal=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(visibility, "package_private");
    }

    #[test]
    fn root_import_publication_migration_applies_to_fresh_and_188_stores() {
        let fresh = open_in_memory_cache();
        let mut upgraded = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version <= 188) {
            upgraded.execute_batch(migration.sql).unwrap();
        }
        upgraded.pragma_update(None, "user_version", 188).unwrap();
        migrate(&mut upgraded).unwrap();
        for conn in [&fresh, &upgraded] {
            for table in [
                "resolution_root_imports",
                "resolution_root_import_segments",
                "resolution_root_import_demands",
            ] {
                assert!(table_exists(conn, table).unwrap(), "missing {table}");
                let fks = conn
                    .prepare(&format!("PRAGMA foreign_key_list({table})"))
                    .unwrap()
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(2)?, row.get::<_, String>(6)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    fks,
                    vec![(
                        "resolution_fragment_interiors".to_owned(),
                        "CASCADE".to_owned()
                    )]
                );
            }
            assert!(current_schema_is_valid(conn).unwrap());
            conn.pragma_update(None, "foreign_keys", false).unwrap();
            let insert = "INSERT INTO resolution_root_import_demands
                (blob_id, import_site, namespace, name, target_kind, target_reference, target_name)
                VALUES(-1, 1, 1, 'bound', ?1, ?2, ?3)";
            for (kind, reference, name) in [
                (None, None, None),
                (Some("same_name_glob"), None, None),
                (Some("named_reference"), Some(2), Some("source")),
            ] {
                conn.execute(insert, rusqlite::params![kind, reference, name])
                    .unwrap();
                conn.execute(
                    "DELETE FROM resolution_root_import_demands WHERE blob_id=-1",
                    [],
                )
                .unwrap();
            }
            for name in [None, Some("")] {
                assert!(
                    conn.execute(insert, rusqlite::params!["named_reference", 2, name])
                        .is_err()
                );
            }
            conn.pragma_update(None, "foreign_keys", true).unwrap();
        }
    }

    #[test]
    fn jvm_external_owner_inventory_migration_applies_to_fresh_and_173_stores() {
        let fresh = open_in_memory_cache();
        assert_eq!(
            cache_migration_version(&fresh).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        for table in [
            "jvm_external_owners",
            "jvm_external_owner_members",
            "jvm_external_owner_supertypes",
        ] {
            assert!(table_exists(&fresh, table).unwrap(), "missing {table}");
        }

        let mut upgraded = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 173)
        {
            upgraded.execute_batch(migration.sql).unwrap();
        }
        upgraded.pragma_update(None, "user_version", 173).unwrap();
        assert!(!table_exists(&upgraded, "jvm_external_owners").unwrap());

        migrate(&mut upgraded).unwrap();

        assert_eq!(
            cache_migration_version(&upgraded).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        for table in [
            "jvm_external_owners",
            "jvm_external_owner_members",
            "jvm_external_owner_supertypes",
        ] {
            assert!(table_exists(&upgraded, table).unwrap(), "missing {table}");
        }
    }

    #[test]
    fn contextual_callable_parameter_lists_migration_applies_to_fresh_and_174_stores() {
        let fresh = open_in_memory_cache();
        assert_eq!(
            cache_migration_version(&fresh).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        let column = fresh
            .query_row(
                "SELECT \"notnull\", dflt_value FROM pragma_table_info('resolution_callable_parameter_lists') WHERE name = 'contextual'",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        assert_eq!(column, (1, "0".to_owned()));

        let mut upgraded = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 174)
        {
            upgraded.execute_batch(migration.sql).unwrap();
        }
        upgraded.pragma_update(None, "user_version", 174).unwrap();
        assert_eq!(
            upgraded
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('resolution_callable_parameter_lists') WHERE name = 'contextual'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        migrate(&mut upgraded).unwrap();

        assert_eq!(
            cache_migration_version(&upgraded).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            upgraded
                .query_row(
                    "SELECT \"notnull\", dflt_value FROM pragma_table_info('resolution_callable_parameter_lists') WHERE name = 'contextual'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (1, "0".to_owned())
        );
    }

    #[test]
    fn php_include_path_migration_preserves_existing_source_imports() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < CURRENT_MIGRATION_VERSION)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", CURRENT_MIGRATION_VERSION - 1)
            .unwrap();

        let blob_id = insert_visibility_blob_fixture(&conn, "php-include-path-migration", None, 1);
        conn.execute(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 1, 3, 0, 0, 0, 0, 0, 0, 1, 0, 'building')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_imports(
               blob_id, import_id, statement, is_wildcard, is_global, path_kind,
               declaration_occurrence_id, declaration_start_byte, declaration_end_byte
             ) VALUES(?1, 0, 'Foo', 0, 0, 'namespace', 0, 0, 3)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
             VALUES(?1, 0, 0, 'Foo')",
            [blob_id],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let preserved: (String, String, String) = conn
            .query_row(
                "SELECT imports.statement, imports.path_kind, segments.segment
                 FROM source_imports AS imports
                 JOIN source_import_segments AS segments
                   USING(blob_id, import_id)
                 WHERE imports.blob_id = ?1 AND imports.import_id = 0",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(preserved, ("Foo".into(), "namespace".into(), "Foo".into()));

        for path_kind in ["file_include", "dynamic_include"] {
            assert_eq!(
                conn.execute(
                    "UPDATE source_imports SET path_kind = ?1
                     WHERE blob_id = ?2 AND import_id = 0",
                    rusqlite::params![path_kind, blob_id],
                )
                .unwrap(),
                1
            );
        }
        assert!(current_schema_is_valid(&conn).unwrap());
        validate_foreign_keys(&conn).unwrap();
    }

    #[test]
    fn migration_157_allows_shared_package_tokens_and_preserves_rows() {
        let mut conn = create_schema_through_146();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'scala', 0)",
            [seeded_oid("scala-import-migration")],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest,
               expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'scala', 'scala', 'test', zeroblob(32), 0, 1, 0, 'building')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_semantic_catalog(
               blob_id, local_key, identity_digest,
               import_source_site, import_start_byte, import_end_byte, import_route_kind
             ) VALUES(?1, 0, zeroblob(32), 0, 0, 1, 'single_type'),
                      (?1, 1, randomblob(32), NULL, NULL, NULL, NULL)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_type_components(
               blob_id, container_slot, constructor, kind, component_slot
             ) VALUES(?1, 0, 0, 0, 1)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest)
             VALUES(?1,0,randomblob(32))",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_package_references(
               blob_id,token_key,domain_key,reference_key,source_site,
               root_scope_key,namespace,lookup_key
             ) VALUES(?1,1,1,1,0,0,'type',1)",
            [blob_id],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(
            conn.query_row(
                "SELECT import_route_kind FROM resolution_semantic_catalog
                 WHERE blob_id=?1 AND local_key=0",
                [blob_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "single_type"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_type_components WHERE blob_id=?1",
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "rebuilding the semantic catalog must preserve its children"
        );
        assert_eq!(
            conn.query_row(
                "SELECT choice_key FROM resolution_package_references WHERE blob_id=?1",
                [blob_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap(),
            None,
            "older package rows retain their authority without a Kotlin choice"
        );
        for index in [
            "resolution_package_references_domain",
            "resolution_package_references_lookup",
            "resolution_package_references_scope",
        ] {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                    [index],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                1,
                "migration must restore index {index}"
            );
        }
        conn.execute(
            "UPDATE resolution_package_references SET choice_key=0 WHERE blob_id=?1",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_semantic_catalog(
               blob_id, local_key, identity_digest,
               import_source_site, import_start_byte, import_end_byte, import_route_kind
             ) VALUES(?1, 2, randomblob(32), 2, 4, 9, 'named'),
                      (?1, 3, randomblob(32), 3, 10, 15, 'star')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_package_references(
               blob_id,token_key,domain_key,reference_key,choice_key,source_site,
               root_scope_key,namespace,lookup_key
             ) VALUES(?1,1,1,2,0,1,0,'type',1)",
            [blob_id],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_package_references
                 WHERE blob_id=?1 AND token_key=1",
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2,
            "one grouped token must retain a package-reference row per site"
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_package_references(
                   blob_id,token_key,domain_key,reference_key,choice_key,source_site,
                   root_scope_key,namespace,lookup_key
                 ) VALUES(?1,0,1,2,NULL,1,0,'type',1)",
                [blob_id],
            )
            .is_err(),
            "one source reference and namespace must remain unique"
        );
        assert_eq!(
            conn.query_row(
                "SELECT choice_key FROM resolution_package_references WHERE blob_id=?1 AND reference_key=1",
                [blob_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap(),
            Some(0)
        );
        assert!(
            conn.execute(
                "UPDATE resolution_package_references SET choice_key=999 WHERE blob_id=?1",
                [blob_id],
            )
            .is_err(),
            "choice_key must reference a semantic catalog key"
        );

        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_semantic_catalog
                 WHERE blob_id=?1 AND import_route_kind IN ('named', 'star')",
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn resolved_file_import_edge_migration_creates_indexed_relations() {
        let conn = open_in_memory_cache();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        for table in [
            "workspace_import_graphs",
            "workspace_import_sources",
            "workspace_import_edges",
            "workspace_import_edge_facts",
            "workspace_import_source_modules",
            "workspace_import_source_bindings",
            "workspace_import_candidate_file_dependencies",
            "workspace_import_route_dependencies",
            "workspace_import_missing_module_dependencies",
        ] {
            assert!(table_exists(&conn, table).unwrap(), "missing {table}");
        }
        let reverse_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master
                   WHERE type = 'index' AND name = 'workspace_import_edges_reverse_idx'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let edge_foreign_keys: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT id)
                 FROM pragma_foreign_key_list('workspace_import_edges')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let edge_fact_foreign_keys: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT id)
                 FROM pragma_foreign_key_list('workspace_import_edge_facts')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let edge_fact_target_foreign_key: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM pragma_foreign_key_list('workspace_import_edge_facts')
                 WHERE \"from\" = 'target_path'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let candidate_indexes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name IN (
                    'workspace_import_candidate_file_dependencies_consulted_idx',
                    'workspace_import_route_dependencies_name_idx',
                    'workspace_import_missing_module_dependencies_key_idx'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let import_ordinal_column: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM pragma_table_info('workspace_import_edge_facts')
                   WHERE name = 'import_ordinal'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let fact_target_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master
                   WHERE type = 'index' AND name = 'workspace_import_edge_facts_target_idx'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let fact_source_target_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master
                   WHERE type = 'index'
                     AND name = 'workspace_import_edge_facts_source_target_idx'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let source_dependency_completeness: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM pragma_table_info('workspace_import_sources')
                   WHERE name = 'complete_resolution_dependencies'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let import_input_digests: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('workspace_import_sources')
                 WHERE name IN ('binding_surface_digest', 'import_rows_digest')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(reverse_index, "missing reverse adjacency index");
        assert_eq!(
            candidate_indexes, 3,
            "missing name-granular import invalidation indexes"
        );
        assert_eq!(
            edge_foreign_keys, 2,
            "edges must reference both source files"
        );
        assert_eq!(
            edge_fact_foreign_keys, 1,
            "edge facts retain the indexed importer-source foreign key"
        );
        assert_eq!(
            edge_fact_target_foreign_key, 0,
            "edge-fact target rows are removed through the indexed target path before source deletion"
        );
        assert!(
            import_ordinal_column,
            "edge facts must preserve import ordinals"
        );
        assert!(fact_target_index, "missing target-side edge-fact index");
        assert!(
            fact_source_target_index,
            "missing source/target edge-fact reconciliation index"
        );
        assert!(
            source_dependency_completeness,
            "source rows must record whether candidate dependencies are complete"
        );
        assert_eq!(
            import_input_digests, 2,
            "source rows must retain both Rust import input digests"
        );
        validate_foreign_keys(&conn).unwrap();
    }

    #[test]
    fn migration_141_widens_import_kinds_and_preserves_catalog_children() {
        let mut conn = create_schema_through_140();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'scala', 0)",
            [seeded_oid("scala-import-migration")],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest,
               expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'scala', 'scala', 'test', zeroblob(32), 0, 1, 0, 'building')",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_semantic_catalog(
               blob_id, local_key, identity_digest,
               import_source_site, import_start_byte, import_end_byte, import_route_kind
             ) VALUES(?1, 0, zeroblob(32), 0, 0, 1, 'single_type'),
                      (?1, 1, randomblob(32), NULL, NULL, NULL, NULL)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_type_components(
               blob_id, container_slot, constructor, kind, component_slot
             ) VALUES(?1, 0, 0, 0, 1)",
            [blob_id],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(
            conn.query_row(
                "SELECT import_route_kind FROM resolution_semantic_catalog
                 WHERE blob_id=?1 AND local_key=0",
                [blob_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "single_type"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_type_components WHERE blob_id=?1",
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "rebuilding the semantic catalog must preserve its children"
        );

        conn.execute(
            "INSERT INTO resolution_semantic_catalog(
               blob_id, local_key, identity_digest,
               import_source_site, import_start_byte, import_end_byte, import_route_kind
             ) VALUES(?1, 2, randomblob(32), 2, 4, 9, 'named'),
                      (?1, 3, randomblob(32), 3, 10, 15, 'star')",
            [blob_id],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_semantic_catalog
                 WHERE blob_id=?1 AND import_route_kind IN ('named', 'star')",
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
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
    #[hardwon(
        "#3708+7224070fdeb7: incomplete aggregate cache evidence was promoted without per-policy completion and provenance"
    )]
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

    fn create_schema_through_140() -> Connection {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 140)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 140).unwrap();
        conn
    }

    fn create_schema_through_146() -> Connection {
        let conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 146)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 146).unwrap();
        conn
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
    #[hardwon("#1544: cache setup failure must identify actionable writable-cache locations")]
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

        if !mode_bits_deny_writes(&workspace_root) {
            std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755))
                .unwrap();
            eprintln!(
                "skipping cache_db::tests::unwritable_workspace_root_reports_the_ways_out: \
                 this process bypasses the injected 0o555 write denial (issue #5090)"
            );
            return;
        }

        let error = open_unified_connection(&db_path).unwrap_err();

        // Restored before any assertion can fail, so the tempdir still cleans up.
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            error.contains(&db_path.display().to_string()),
            "the denied path must be named: {error}"
        );
        assert_elevated_permission_advice(&error, &workspace_root);
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
    #[hardwon("#1544: cache setup failure in a managed directory must report recovery paths")]
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

        if !mode_bits_deny_writes(&cache_dir) {
            std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!(
                "skipping cache_db::tests::unwritable_cache_directory_reports_the_ways_out: \
                 this process bypasses the injected 0o555 write denial (issue #5090)"
            );
            return;
        }

        let error = open_unified_connection(&db_path).unwrap_err();

        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_elevated_permission_advice(&error, &cache_dir);
    }

    #[test]
    #[hardwon("8133f3a74309: fresh stores and analyzer processes replayed historical migrations")]
    fn fresh_cache_matches_the_historical_migration_chain() {
        let historical = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS {
            historical.execute_batch(migration.sql).unwrap();
        }
        let before = now_unix_seconds();
        let conn = open_in_memory_cache();
        let after = now_unix_seconds();

        assert_eq!(
            schema_object_definitions(&conn).unwrap(),
            schema_object_definitions(&historical).unwrap()
        );
        assert_eq!(
            schema_object_definitions_sha256(&conn).unwrap(),
            CURRENT_SCHEMA_OBJECTS_SHA256
        );
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        validate_foreign_keys(&conn).unwrap();

        for sql in [
            "SELECT id, next_generation FROM analysis_generation_sequence",
            "SELECT id, schema_version, semantic_schema_version, analyzer_schema_version,
                    blobs_at_last_gc, gc_claim_until, embed_fingerprint, chunker_version
             FROM cache_state",
        ] {
            let rows = |connection: &Connection| {
                let mut statement = connection.prepare(sql).unwrap();
                let column_count = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..column_count)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            };
            assert_eq!(rows(&conn), rows(&historical), "{sql}");
        }
        let last_gc_at: i64 = conn
            .query_row(
                "SELECT last_gc_at FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!((before..=after).contains(&last_gc_at));
        let type_name_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master
                   WHERE type='index' AND name='source_rust_type_segments_name'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(type_name_index, "schema 156 installs the type-name index");
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
    fn field_slot_source_migration_preserves_existing_atoms() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 222) {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 221).unwrap();
        conn.execute_batch("INSERT INTO class_set_field_slot_indexes VALUES(
            1,'python',zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),1,
            zeroblob(32),1,1,0,0,'complete',0,0,0);
            INSERT INTO class_set_field_slots VALUES(1,0,'external',NULL,'Owner',NULL,'owner','item');
            INSERT INTO class_set_field_slot_atoms VALUES(1,0,0,'unknown',NULL,NULL,NULL,NULL,
            'field_slot_incomplete','app.py',0,0,0,1,0,1,'unknown');").unwrap();
        migrate(&mut conn).unwrap();
        let row: (String, String, i64) = conn.query_row(
            "SELECT source_kind, unknown_reason, source_end_byte FROM class_set_field_slot_atoms",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        assert_eq!(row, ("unknown".into(), "field_slot_incomplete".into(), 1));
        assert!(current_schema_is_valid(&conn).unwrap());
    }
    #[test]
    fn compilation_import_migration_preserves_roots_and_cascades_both_levels() {
        let mut upgraded = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 221) {
            upgraded.execute_batch(migration.sql).unwrap();
        }
        let previous = POST_BASELINE_MIGRATIONS
            .iter()
            .rfind(|m| m.version < 221)
            .unwrap()
            .version;
        upgraded
            .pragma_update(None, "user_version", previous)
            .unwrap();
        let fresh = open_in_memory_cache();
        let seed = |conn: &Connection| {
            conn.execute_batch(
                "INSERT INTO blobs(id,blob_oid,lang,generation)
                 VALUES(1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','csharp',0);
                 INSERT INTO resolution_fragment_interiors(
                   blob_id,lang,semantic_language,producer_epoch,interior_digest,
                   expected_semantic_site_count,logical_rows,payload_bytes,publication_state)
                 VALUES(1,'csharp','csharp','test',zeroblob(32),0,3,0,'building');
                 INSERT INTO resolution_root_imports(blob_id,import_site,root_scope,anchor,kind)
                 VALUES(1,1,0,'lexical','glob'),(1,2,0,'lexical','glob');",
            )
            .unwrap();
        };
        seed(&upgraded);
        migrate(&mut upgraded).unwrap();
        seed(&fresh);
        for conn in [&fresh, &upgraded] {
            assert!(current_schema_is_valid(conn).unwrap());
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM resolution_root_imports", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                2
            );
            assert_eq!(conn.query_row("SELECT expected_compilation_import_count FROM resolution_fragment_interiors WHERE blob_id=1", [], |r| r.get::<_,i64>(0)).unwrap(),0);
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM resolution_compilation_imports",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            conn.execute(
                "INSERT INTO resolution_compilation_imports VALUES(1,1),(1,2)",
                [],
            )
            .unwrap();
            assert!(
                conn.execute("INSERT INTO resolution_compilation_imports VALUES(1,1)", [])
                    .is_err()
            );
            assert!(
                conn.execute("INSERT INTO resolution_compilation_imports VALUES(1,3)", [])
                    .is_err()
            );
            let sites = conn.prepare("SELECT import_site FROM resolution_compilation_imports WHERE blob_id=?1 ORDER BY import_site").unwrap().query_map([1], |r| r.get::<_,i64>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(sites, [1, 2]);
            let plan = conn.prepare("EXPLAIN QUERY PLAN SELECT import_site FROM resolution_compilation_imports WHERE blob_id=?1 ORDER BY import_site").unwrap().query_map([1], |r| r.get::<_,String>(3)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert!(
                plan.iter()
                    .any(|line| line.contains("USING PRIMARY KEY (blob_id=?)")),
                "{plan:?}"
            );
            validate_foreign_keys(conn).unwrap();
            conn.execute(
                "DELETE FROM resolution_root_imports WHERE blob_id=1 AND import_site=1",
                [],
            )
            .unwrap();
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM resolution_compilation_imports",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            conn.execute(
                "DELETE FROM resolution_fragment_interiors WHERE blob_id=1",
                [],
            )
            .unwrap();
            for table in ["resolution_root_imports", "resolution_compilation_imports"] {
                assert_eq!(
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    0,
                    "{table}"
                );
            }
            validate_foreign_keys(conn).unwrap();
        }
    }

    #[test]
    fn deferred_member_selection_migration_preserves_existing_calls() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 219)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        let previous_version = POST_BASELINE_MIGRATIONS
            .iter()
            .rfind(|migration| migration.version < 219)
            .unwrap()
            .version;
        conn.pragma_update(None, "user_version", previous_version)
            .unwrap();
        conn.execute("INSERT INTO blobs(blob_oid, lang, generation) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'go', 0)", []).unwrap();
        let blob = conn.last_insert_rowid();
        conn.execute("INSERT INTO semantic_ir_publications(blob_id, lang, producer_epoch, content_digest, source_bytes, outcome, procedure_count, logical_rows, payload_bytes, go_predeclared_builtins, publication_state) VALUES(?1, 'go', 'before-member-selection', zeroblob(32), 17, 0, 1, 2, 0, jsonb('[]'), 'complete')", [blob]).unwrap();
        conn.execute("INSERT INTO semantic_ir_call_sites(blob_id, procedure, call_site, point, invocation_mode, execution_timing, callee, receiver, result, thrown, normal_results, target_resolution, targets, target_evidence, normal_continuation, normal_target, exceptional_continuation, exceptional_target, source, evidence) VALUES(?1, 0, 0, 3, 0, 0, 1, 2, NULL, 5, jsonb('[6,7]'), 2, NULL, 0, 0, 4, 1, NULL, 0, 0)", [blob]).unwrap();
        migrate(&mut conn).unwrap();
        let actual = conn.query_row("SELECT point, receiver, thrown, json(normal_results), member, receiver_place_kind, receiver_place_locator, receiver_place_location, receiver_pointer_depth FROM semantic_ir_call_sites WHERE blob_id = ?1 AND procedure = 0 AND call_site = 0", [blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?, (4..9).map(|index| row.get::<_, Option<i64>>(index)).collect::<rusqlite::Result<Vec<_>>>()?))).unwrap();
        assert_eq!(actual, (3, 2, 5, "[6,7]".to_owned(), vec![None; 5]));
        validate_foreign_keys(&conn).unwrap();
        assert!(current_schema_is_valid(&conn).unwrap());
        conn.execute("DELETE FROM blobs WHERE id = ?1", [blob])
            .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM semantic_ir_call_sites", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
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
        for code in [4, 5, 6, 7, 8] {
            conn.execute(
                "INSERT INTO resolution_type_transfers VALUES(?1, 1, ?2, 3, 0, 0, 0, ?2, NULL)",
                rusqlite::params![blob, code],
            )
            .unwrap();
        }
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_transfers VALUES(?1, 1, 9, 3, 0, 0, 0, 9, NULL)",
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
    fn generic_type_alias_migration_adds_validated_relational_rows() {
        let mut conn = create_current_baseline_without_migration();
        for migration in POST_BASELINE_MIGRATIONS
            .iter()
            .filter(|migration| migration.version < 139)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 138).unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
            ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        .unwrap();
        let blob = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest,
               expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'rust', 'rust', 'alias-test', zeroblob(32), 0, 1, 0, 'building')",
            [blob],
        )
        .unwrap();
        for key in 1..=5 {
            conn.execute(
                "INSERT INTO resolution_semantic_catalog(blob_id, local_key, identity_digest)
                 VALUES(?1, ?2, randomblob(32))",
                rusqlite::params![blob, key],
            )
            .unwrap();
        }

        migrate(&mut conn).unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        conn.execute(
            "INSERT INTO resolution_type_arguments
               (blob_id, application_slot, ordinal, argument_slot, indirection_delta,
                reference_indirection_delta)
             VALUES(?1, 1, 0, 2, 1, 1)",
            [blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_generic_type_alias_parameters
               (blob_id, alias_definition, ordinal, parameter_definition, target_slot,
                indirection_delta, reference_indirection_delta)
             VALUES(?1, 3, 0, 4, 5, 0, 0)",
            [blob],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_arguments
               (blob_id, application_slot, ordinal, argument_slot, indirection_delta,
                reference_indirection_delta)
             VALUES(?1, 1, -1, 2, 0, 0)",
                [blob],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_generic_type_alias_parameters
               (blob_id, alias_definition, ordinal, parameter_definition, target_slot,
                indirection_delta, reference_indirection_delta)
             VALUES(?1, 3, 1, 4, 5, 0, 0)",
                [blob],
            )
            .is_err()
        );
        assert!(current_schema_is_valid(&conn).unwrap());

        conn.execute("DELETE FROM blobs WHERE id=?1", [blob])
            .unwrap();
        for table in [
            "resolution_type_arguments",
            "resolution_generic_type_alias_parameters",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} cascades with its blob");
        }
    }

    #[test]
    #[hardwon(
        "77a06ad02155: adding lexical import scopes must migrate existing cache blobs without loss"
    )]
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
               'complete', 'exhaustive', 'rows', jsonb('{\"rows\":[]}'),
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
                   'complete', 'exhaustive', 'rows', jsonb('{}'), zeroblob(32), 100
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
                       'complete', 'exhaustive', ?3, jsonb('{}'), zeroblob(32), 100
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
               'complete', 'exhaustive', 'rows', jsonb('{\"rows\":[]}'), zeroblob(32), 100
             )",
            [],
        )
        .unwrap();

        // Only exhaustive, complete units are publishable at all.
        let bounded = conn
            .execute("UPDATE policy_units SET budget_mode = 'bounded'", [])
            .unwrap_err();
        assert!(bounded.to_string().contains("CHECK constraint failed"));

        // A product must be strict JSONB so replay accounting stays readable
        // through SQL's JSON functions.
        let opaque_product = conn
            .execute(
                "UPDATE policy_units SET product = CAST('not json' AS BLOB)",
                [],
            )
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
    #[hardwon(
        "de6802c91638: workspace streaming readers could retain an unbounded mmap-backed cache"
    )]
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
    #[hardwon(
        "#4456: a deferred read-then-write transaction got SQLITE_BUSY without waiting while another connection held the write lock"
    )]
    fn writable_connection_transaction_waits_for_an_existing_writer() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        let mut connection_a = open_unified_connection(&db_path).unwrap();
        let writer_holds_lock = Arc::new(Barrier::new(2));
        let writer_barrier = Arc::clone(&writer_holds_lock);
        let writer_path = db_path.clone();
        let writer = thread::spawn(move || {
            let mut connection_b = open_unified_connection(&writer_path).unwrap();
            let transaction = connection_b.transaction().unwrap();
            transaction
                .execute(
                    "UPDATE cache_state SET last_gc_at = last_gc_at + 1 WHERE id = 1",
                    [],
                )
                .unwrap();
            writer_barrier.wait();
            thread::sleep(Duration::from_millis(300));
            transaction.commit().unwrap();
        });

        // A deferred transaction would read here, then fail the write upgrade
        // with SQLITE_BUSY at once; SQLite skips the busy handler for upgrades.
        writer_holds_lock.wait();
        let transaction = connection_a.transaction().unwrap();
        let last_gc_at: i64 = transaction
            .query_row(
                "SELECT last_gc_at FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        transaction
            .execute(
                "UPDATE cache_state SET last_gc_at = ?1 WHERE id = 1",
                [last_gc_at + 1],
            )
            .unwrap();
        transaction.commit().unwrap();
        writer.join().unwrap();
    }

    #[test]
    #[hardwon("#885: simultaneous first opens raced SQLite bootstrap and schema migration")]
    fn concurrent_fresh_cache_openers_serialize_schema_migration() {
        const OPENERS: usize = 16;

        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        // An empty template directory, so one of the openers builds the store
        // rather than every opener copying a template another run published.
        let template_dir = temp.path().join("templates");
        let barrier = Arc::new(Barrier::new(OPENERS));
        let results = thread::scope(|scope| {
            let handles = (0..OPENERS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let db_path = db_path.clone();
                    let template_dir = template_dir.as_path();
                    scope.spawn(move || {
                        barrier.wait();
                        let conn = open_unified_connection_with_template_dir(
                            &db_path,
                            Some(template_dir),
                        )?;
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
    #[hardwon("#1173: one canonical cache path must reuse a lock cell across concurrent openers")]
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
    #[hardwon("#1173: independent cache paths must not serialize behind one lock cell")]
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
    #[hardwon(
        "#885: bootstrap must not claim populated mode-zero stores were converted without VACUUM"
    )]
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

    fn assert_populated_legacy_store(
        conn: &Connection,
        expected_rows: i64,
        expected_application_id: i64,
        expected_user_version: i64,
    ) {
        assert_eq!(connection_page_size(conn), 4096);
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
            expected_rows
        );
        assert_eq!(
            conn.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            expected_application_id
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            expected_user_version
        );
        assert!(quick_check_is_ok(conn).unwrap());
    }

    #[test]
    #[hardwon(
        "#2326: fresh cache stores used small pages and spent excessive time in reconciliation"
    )]
    fn fresh_cache_store_uses_cache_page_size() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db_file_name());
        // An empty template directory, so this open builds the store and
        // publishes the template instead of copying one another run published.
        let template_dir = temp.path().join("templates");

        let conn =
            open_unified_connection_with_template_dir(&db_path, Some(&template_dir)).unwrap();
        assert!(template_dir.join(STORE_TEMPLATE.file_name()).is_file());

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
    #[hardwon("#2326: page-size tuning stalled WAL readers and risked rebuilding populated stores")]
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

        assert_populated_legacy_store(&conn, 3, 2462, 1234);

        // Reconfiguring the same legacy store is safe and remains rewrite-free.
        configure_connection(&mut conn).unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert!(quick_check_is_ok(&conn).unwrap());
    }

    #[test]
    #[hardwon(
        "#2326: opening a populated rollback store must not rebuild it just to tune page size"
    )]
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

        assert_populated_legacy_store(&conn, 1, 2462, 5678);

        configure_connection(&mut conn).unwrap();
        assert_eq!(connection_page_size(&conn), 4096);
        assert!(quick_check_is_ok(&conn).unwrap());
    }

    #[test]
    #[hardwon("#885: retry SQLite BUSY but surface SQLITE_LOCKED without retrying")]
    fn initialization_retry_retries_busy_but_not_locked() {
        let mut busy_attempts = 0;
        let value = retry_initialization_phase_with(
            "test busy phase",
            Duration::from_secs(1),
            |_| {},
            || {
                busy_attempts += 1;
                if busy_attempts < 3 {
                    Err(InitializationPhaseError::Sqlite(
                        crate::test_support::sqlite_error(rusqlite::ffi::SQLITE_BUSY),
                    ))
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
                Err::<(), _>(InitializationPhaseError::Sqlite(
                    crate::test_support::sqlite_error(rusqlite::ffi::SQLITE_LOCKED),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(locked_attempts, 1);
        assert!(error.contains("test locked phase SQLite error"), "{error}");
        assert!(!error.contains("timed out"), "{error}");
    }

    #[test]
    #[hardwon("#885: an expired initialization deadline must not sleep before returning")]
    fn initialization_retry_reports_busy_deadline_without_sleeping() {
        let mut attempts = 0;
        let error = retry_initialization_phase_with(
            "test timeout phase",
            Duration::ZERO,
            |_| panic!("zero-deadline retry must not sleep"),
            || {
                attempts += 1;
                Err::<(), _>(InitializationPhaseError::Sqlite(
                    crate::test_support::sqlite_error(rusqlite::ffi::SQLITE_BUSY),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(error.contains("test timeout phase timed out"), "{error}");
    }

    fn assert_pre_migration_schema_object_is_removed(
        conn: &mut Connection,
        object_type: &str,
        object_name: &str,
    ) {
        migrate(conn).unwrap();

        assert_eq!(
            cache_migration_version(conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        let object_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2
                 )",
                rusqlite::params![object_type, object_name],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !object_exists,
            "{object_type} {object_name} survived rebuild"
        );
        assert!(current_schema_is_valid(conn).unwrap());
    }

    #[test]
    fn incomplete_pre_migration_cache_is_rebuilt() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        assert_pre_migration_schema_object_is_removed(&mut conn, "table", "legacy_cache");
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_table_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        assert_pre_migration_schema_object_is_removed(&mut conn, "table", "legacy_cache");
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

        assert_pre_migration_schema_object_is_removed(&mut conn, "view", "legacy_view");
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

    fn assert_concurrent_upgrade_publishes_complete_legacy_ignore(
        initial_gitignore: Option<&[u8]>,
        failure_context: &'static str,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let project_dir = temp.path().join(crate::gitblob::PROJECT_DIR_NAME);
        std::fs::create_dir(&project_dir).unwrap();
        if let Some(content) = initial_gitignore {
            std::fs::write(project_dir.join(".gitignore"), content).unwrap();
        }
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
                .expect(failure_context);
        }

        assert_eq!(
            std::fs::read(project_dir.join(".gitignore")).unwrap(),
            GENERATED_LEGACY_PROJECT_GITIGNORE
        );
        assert!(project_dir.join(LEGACY_CACHE_DB_FILE_NAME).exists());
    }

    #[test]
    fn concurrent_default_layout_upgrades_publish_one_complete_narrow_ignore() {
        assert_concurrent_upgrade_publishes_complete_legacy_ignore(
            Some(GENERATED_CACHE_GITIGNORE),
            "concurrent upgrade",
        );
    }

    #[test]
    fn concurrent_upgrades_publish_a_complete_ignore_when_it_was_missing() {
        assert_concurrent_upgrade_publishes_complete_legacy_ignore(
            None,
            "concurrent missing-ignore upgrade",
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
    #[hardwon(
        "#1197: generated cache files were not self-ignored and reopening could overwrite user edits"
    )]
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
    #[hardwon("#1197: cache ignore setup must not hide unrelated workspace directories")]
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
}
