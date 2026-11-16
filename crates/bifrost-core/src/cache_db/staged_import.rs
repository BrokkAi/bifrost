//! Construction authority for a newly allocated, unpublished import only.
//! Child privacy prevents production reset access from normal store openers.
//! The advisory builder lock is not same-UID OS security; crash durability
//! remains the existing SQLite commit/close and no-clobber publication policy.
use super::*;

const NONCE_GUARD_SQL: &str =
    include_str!("../../migrations/cache/publication-lineage-nonce-guard.sql");

// Field order matters on failure: close SQLite, delete its private stage, then
// release the actual builder lock. No raw connection/path conversion escapes.
struct StagedImport {
    connection: Option<Connection>,
    staged: tempfile::TempPath,
    destination: PathBuf,
    source: PathBuf,
    _builder_lock: std::fs::File,
}

impl StagedImport {
    fn copy_selected_source(
        destination: &Path,
        source: &Path,
        builder_lock: std::fs::File,
    ) -> Result<Self> {
        let source_conn = open_store_connection(
            source,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            ConnectionRole::UpgradeSource,
        )
        .map_err(|error| {
            format!(
                "cache DB upgrade SQLite error reading {}: {error}",
                source.display()
            )
        })?;
        refuse_pre_native_import(&source_conn, source)?;
        let staged = tempfile::Builder::new()
            .prefix(STAGED_UPGRADE_PREFIX)
            .tempfile_in(
                destination
                    .parent()
                    .expect("prepared destination has a parent"),
            )
            .map_err(|error| format!("failed to stage cache DB upgrade: {error}"))?
            .into_temp_path();
        source_conn
            .backup(rusqlite::MAIN_DB, &staged, None)
            .map_err(|error| {
                format!(
                    "cache DB upgrade SQLite error copying {}: {error}",
                    source.display()
                )
            })?;
        let connection = open_store_connection(
            &staged,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            ConnectionRole::UpgradeTarget,
        )
        .map_err(|error| format!("cache DB upgrade SQLite error: {error}"))?;
        Ok(Self {
            connection: Some(connection),
            staged,
            destination: destination.to_owned(),
            source: source.to_owned(),
            _builder_lock: builder_lock,
        })
    }

    /// Migrate the private copy to this build's schema and prove the result
    /// before anyone can see it.
    ///
    /// Publishing first and migrating afterwards is what made a failed upgrade
    /// unrecoverable: the half-migrated copy already carried this build's file
    /// name, so every later open found the file present, skipped the upgrade, and
    /// failed the same migration again. Nothing here is visible under that name
    /// until the migration has run, the schema matches this build's exactly, and
    /// `quick_check` passes; a failure drops the staged path and leaves the source
    /// untouched.
    fn complete_and_publish(mut self) -> Result<()> {
        let conn = self
            .connection
            .as_mut()
            .expect("private stage owns its connection");
        install_busy_timeout(conn)?;
        refuse_pre_native_import(conn, &self.source)?;
        migrate(conn)?;
        // Check shape before the creation exception, without repeating the
        // full-file quick_check that runs once after guard restoration.
        if !current_schema_shape_is_valid(conn)? {
            return Err("cache DB import does not match the current schema".to_owned());
        }
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| format!("cache DB import creation transaction: {error}"))?;
            let previous_nonce = publication_lineage::require_publication_nonce(&tx)
                .map_err(|error| error.to_string())?;
            let next: i64 = tx
                .query_row(
                    "SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| format!("cache DB import clock read: {error}"))?;
            // Native-approved construction exception: only this newly created
            // private destination, never the source or an already opened store.
            // Every other allocator/sealing guard remains active.
            tx.execute_batch("DROP TRIGGER blob_publication_sequence_nonce_immutable;")
                .map_err(|error| format!("cache DB import nonce guard: {error}"))?;
            let changed = tx
                .execute(
                    "UPDATE blob_publication_witness_sequence SET store_nonce = NULL WHERE id = 1",
                    [],
                )
                .map_err(|error| format!("cache DB import namespace creation: {error}"))?;
            if changed != 1 {
                return Err(format!(
                    "cache DB import namespace matched {changed} rows, expected 1"
                ));
            }
            let nonce = mint_publication_nonce(&tx)?;
            if nonce == previous_nonce {
                return Err("cache DB import did not create a distinct namespace".to_owned());
            }
            tx.execute_batch(NONCE_GUARD_SQL)
                .map_err(|error| format!("cache DB import nonce guard restore: {error}"))?;
            verify_upgraded_store(&tx, &self.source)?;
            publication_lineage::require_publication_nonce(&tx)
                .map_err(|error| error.to_string())?;
            let current: i64 = tx
                .query_row(
                    "SELECT next_witness FROM blob_publication_witness_sequence WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| format!("cache DB import clock validation: {error}"))?;
            if current != next {
                return Err(format!(
                    "cache DB import changed counter from {next} to {current}"
                ));
            }
            tx.commit()
                .map_err(|error| format!("cache DB import creation commit: {error}"))?;
        }
        close_created_store(
            self.connection
                .take()
                .expect("private stage owns its connection"),
        )?;
        match self.staged.persist_noclobber(&self.destination) {
            Ok(()) => {
                eprintln!(
                    "Bifrost cache upgraded {} to schema version {} as {}",
                    self.source.display(),
                    CURRENT_MIGRATION_VERSION,
                    self.destination.display()
                );
                Ok(())
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(format!(
                "failed to atomically publish upgraded cache DB {}: {}",
                self.destination.display(),
                error.error
            )),
        }
    }
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
pub(super) fn import_newest_older_store(db_path: &Path) -> Result<()> {
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
    StagedImport::copy_selected_source(db_path, &source, upgrade_lock)?.complete_and_publish()
}

/// Drive the real consuming constructor through a SQLite authorization failure
/// exactly when it tries to restore the guard. No production fault mode/API.
#[cfg(test)]
pub(super) fn assert_failed_creation_is_unpublished(
    cache_dir: &Path,
    source: &Path,
    destination: &Path,
) {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let lock = open_upgrade_lock(cache_dir).unwrap();
    lock.lock().unwrap();
    let mut staged = StagedImport::copy_selected_source(destination, source, lock).unwrap();
    let updates = Arc::new(AtomicUsize::new(0));
    let seen = updates.clone();
    staged
        .connection
        .as_mut()
        .unwrap()
        .authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Update {
                table_name: "blob_publication_witness_sequence",
                column_name: "store_nonce",
            } => {
                seen.fetch_add(1, Ordering::SeqCst);
                Authorization::Allow
            }
            AuthAction::CreateTrigger {
                trigger_name: "blob_publication_sequence_nonce_immutable",
                ..
            } => Authorization::Deny,
            _ => Authorization::Allow,
        }))
        .unwrap();
    let error = staged.complete_and_publish().unwrap_err();
    assert!(error.contains("nonce guard restore"), "{error}");
    assert_eq!(
        updates.load(Ordering::SeqCst),
        2,
        "failure must follow demint AND mint"
    );
    assert!(!destination.exists());
    assert!(staged_copy_paths(cache_dir).unwrap().is_empty());
    let original = Connection::open(source).unwrap();
    assert!(
        original
            .execute(
                "UPDATE blob_publication_witness_sequence SET store_nonce=NULL",
                []
            )
            .is_err()
    );
}
