//! Issue #1589: the persisted store is keyed by schema version, not migrated.
//!
//! One shared file means the newest build to touch it decides the schema for
//! every checkout of the repository, and older builds then refuse the whole
//! file. Naming the file for the schema that wrote it lets versions sit side
//! by side: a build opens exactly its own, seeds it once from the newest
//! store it can carry forward, and never writes the source.

use std::fs::{File, FileTimes};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use brokk_bifrost::analyzer::store::AnalyzerStore;
use brokk_bifrost::{cache_db, cache_gc};
use git2::{ObjectType, Oid};

fn current_store(cache_dir: &Path) -> PathBuf {
    cache_dir.join(cache_db::cache_db_file_name())
}

fn store_for_version(cache_dir: &Path, version: i64) -> PathBuf {
    cache_dir.join(cache_db::cache_db_file_name_for_version(version))
}

fn legacy_store(cache_dir: &Path) -> PathBuf {
    cache_dir.join(cache_db::LEGACY_CACHE_DB_FILE_NAME)
}

fn oid(content: &[u8]) -> Oid {
    Oid::hash_object(ObjectType::Blob, content).unwrap()
}

/// Register `blob` in a store at `path`, leaving it fully migrated and closed.
fn seed_store(path: &Path, blob: Oid) {
    let store = AnalyzerStore::open_persistent(path).unwrap();
    let generation = store
        .ensure_language_epoch_value("python", "versioned-store-test")
        .unwrap();
    store.register_blobs(&[blob], "python", generation).unwrap();
    drop(store);
}

fn store_user_version(path: &Path) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

fn set_modified(path: &Path, age: Duration) {
    let times = FileTimes::new().set_modified(SystemTime::now() - age);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(times)
        .unwrap();
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_first_open_creates_only_this_builds_store() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();

    seed_store(&current_store(cache_dir), oid(b"fresh"));

    assert_eq!(
        store_user_version(&current_store(cache_dir)),
        cache_db::cache_db_schema_version()
    );
    assert!(
        !legacy_store(cache_dir).exists(),
        "{:?}",
        file_names(cache_dir)
    );
}

#[test]
fn an_upgrade_imports_the_newest_older_store_and_leaves_it_in_place() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let current_version = cache_db::cache_db_schema_version();

    let older = store_for_version(cache_dir, current_version - 1);
    let oldest = store_for_version(cache_dir, current_version - 2);
    let carried = oid(b"carried forward");
    let stale = oid(b"only in the oldest store");
    seed_store(&oldest, stale);
    seed_store(&older, carried);
    let older_before = std::fs::read(&older).unwrap();

    let imported = AnalyzerStore::open_persistent(&current_store(cache_dir)).unwrap();

    assert!(
        imported.contains_blob(carried, "python").unwrap(),
        "the newest older store must be the one imported"
    );
    assert!(
        !imported.contains_blob(stale, "python").unwrap(),
        "an older store must not win over a newer one"
    );
    assert_eq!(
        store_user_version(&current_store(cache_dir)),
        current_version,
        "the copy must come out at this build's schema"
    );
    assert_eq!(
        std::fs::read(&older).unwrap(),
        older_before,
        "the source must stay byte-identical for the checkouts still using it"
    );
    let names = file_names(cache_dir);
    assert!(
        !names
            .iter()
            .any(|name| name.starts_with(".bifrost-cache-import")),
        "the staged copy must be published or dropped, not left behind: {names:?}"
    );
}

#[test]
fn a_legacy_store_from_a_newer_schema_is_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let ahead = oid(b"written by a newer build");
    seed_store(&legacy_store(cache_dir), ahead);
    rusqlite::Connection::open(legacy_store(cache_dir))
        .unwrap()
        .pragma_update(
            None,
            "user_version",
            cache_db::cache_db_schema_version() + 1,
        )
        .unwrap();

    let store = AnalyzerStore::open_persistent(&current_store(cache_dir)).unwrap();

    assert!(
        !store.contains_blob(ahead, "python").unwrap(),
        "a store this build cannot migrate must not be dragged backwards"
    );
    assert_eq!(
        store_user_version(&current_store(cache_dir)),
        cache_db::cache_db_schema_version()
    );
}

#[test]
fn a_legacy_store_this_build_can_migrate_is_imported() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let carried = oid(b"from the unversioned store");
    seed_store(&legacy_store(cache_dir), carried);
    let legacy_before = std::fs::read(legacy_store(cache_dir)).unwrap();

    let store = AnalyzerStore::open_persistent(&current_store(cache_dir)).unwrap();

    assert!(store.contains_blob(carried, "python").unwrap());
    assert_eq!(
        std::fs::read(legacy_store(cache_dir)).unwrap(),
        legacy_before,
        "a build older than versioning still opens this file"
    );
}

#[test]
fn files_that_are_not_stores_are_never_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let hidden = oid(b"inside a backup");
    let backup = cache_dir.join("bifrost_cache.db.schema14.bak");
    seed_store(&backup, hidden);
    for foreign in ["bifrost_cache.v.db", "bifrost_cache.vnext.db", "other.db"] {
        seed_store(&cache_dir.join(foreign), hidden);
    }

    let store = AnalyzerStore::open_persistent(&current_store(cache_dir)).unwrap();

    assert!(
        !store.contains_blob(hidden, "python").unwrap(),
        "only version-suffixed stores are candidates, but {:?} was in reach",
        file_names(cache_dir)
    );
}

#[test]
fn collection_removes_a_disused_older_store_and_keeps_everything_else() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let current_version = cache_db::cache_db_schema_version();

    let disused = store_for_version(cache_dir, current_version - 2);
    let recent = store_for_version(cache_dir, current_version - 1);
    let legacy = legacy_store(cache_dir);
    let backup = cache_dir.join("bifrost_cache.db.schema14.bak");
    for path in [&disused, &recent, &legacy, &backup] {
        seed_store(path, oid(b"content"));
    }
    seed_store(&current_store(cache_dir), oid(b"content"));

    let beyond_grace = Duration::from_secs((cache_gc::VERSION_STORE_GRACE_SECS + 24 * 3600) as u64);
    for path in [&disused, &legacy, &backup] {
        for suffix in cache_db::STORE_FILE_SUFFIXES {
            let sidecar = cache_db::store_file_with_suffix(path, suffix);
            if sidecar.exists() {
                set_modified(&sidecar, beyond_grace);
            }
        }
    }

    let removed = cache_gc::sweep_disused_version_stores(cache_dir).unwrap();

    assert_eq!(removed, vec![disused.clone()]);
    assert!(!disused.exists());
    assert!(recent.exists(), "a store in recent use must survive");
    assert!(
        current_store(cache_dir).exists(),
        "this build's own store is never a candidate"
    );
    assert!(
        legacy.exists(),
        "the unversioned store is the only file a pre-versioning build can open"
    );
    assert!(backup.exists(), "a hand-made backup is not ours to delete");
}

/// The sweep is wired into the collection the workspace already runs, not
/// only reachable from a test.
#[test]
fn workspace_collection_sweeps_disused_older_stores() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let repo = git2::Repository::init(&root).unwrap();
    let store = AnalyzerStore::open_for_workspace(&root).unwrap();
    let cache_dir = brokk_bifrost::gitblob::cache_db_path(&root)
        .parent()
        .unwrap()
        .to_path_buf();

    let disused = store_for_version(&cache_dir, cache_db::cache_db_schema_version() - 1);
    seed_store(&disused, oid(b"content"));
    let beyond_grace = Duration::from_secs((cache_gc::VERSION_STORE_GRACE_SECS + 24 * 3600) as u64);
    for suffix in cache_db::STORE_FILE_SUFFIXES {
        let sidecar = cache_db::store_file_with_suffix(&disused, suffix);
        if sidecar.exists() {
            set_modified(&sidecar, beyond_grace);
        }
    }

    let outcome = cache_gc::force_gc_for_analyzer(&store, &repo).unwrap();

    assert!(outcome.ran);
    assert_eq!(outcome.version_stores_removed, 1);
    assert!(!disused.exists(), "{:?}", file_names(&cache_dir));
}

#[test]
fn a_wal_sidecar_keeps_a_live_store_out_of_collection() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let older = store_for_version(cache_dir, cache_db::cache_db_schema_version() - 1);
    let live = AnalyzerStore::open_persistent(&older).unwrap();

    let beyond_grace = Duration::from_secs((cache_gc::VERSION_STORE_GRACE_SECS + 24 * 3600) as u64);
    set_modified(&older, beyond_grace);

    let removed = cache_gc::sweep_disused_version_stores(cache_dir).unwrap();

    assert!(
        removed.is_empty(),
        "a WAL-mode store barely touches its main file; {:?} must still count as live",
        file_names(cache_dir)
    );
    assert!(older.exists());
    drop(live);
}

/// Only this build's migrations are reachable from a test, so an "older"
/// store here differs by name rather than by schema. That is exactly what the
/// design keys on: the name decides which file a build opens, and this pins
/// that two of them stay independent.
#[test]
fn two_schema_versions_coexist_in_one_cache_dir() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path();
    let older = store_for_version(cache_dir, cache_db::cache_db_schema_version() - 1);
    let shared = oid(b"present in both");
    seed_store(&older, shared);

    let current = AnalyzerStore::open_persistent(&current_store(cache_dir)).unwrap();
    let only_current = oid(b"written after the upgrade");
    let generation = current
        .ensure_language_epoch_value("python", "versioned-store-test")
        .unwrap();
    current
        .register_blobs(&[only_current], "python", generation)
        .unwrap();

    let older_store = AnalyzerStore::open_persistent(&older).unwrap();
    assert!(older_store.contains_blob(shared, "python").unwrap());
    assert!(
        !older_store.contains_blob(only_current, "python").unwrap(),
        "an older checkout must not see the newer version's writes"
    );
    assert!(current.contains_blob(shared, "python").unwrap());
    assert!(current.contains_blob(only_current, "python").unwrap());
}
