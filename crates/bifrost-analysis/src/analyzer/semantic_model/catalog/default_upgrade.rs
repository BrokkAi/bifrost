//! Copy older default catalogs; explicit paths retain in-place migration.
use super::*;
use rusqlite::OpenFlags;
use std::fs;
use std::io::Read;
const DB: &str = "catalog.db";
const REPORT: &str = "upgrade-report.json";
const INITIALIZED: &str = "default-initialized.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct InitializationState {
    catalog_version: i64,
}

fn initialization_version(root: &Path) -> Result<Option<i64>, CatalogError> {
    let file = match fs::File::open(root.join(INITIALIZED)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CatalogError::io(
                "read default catalog initialization marker",
                error,
            ));
        }
    };
    let mut bytes = Vec::new();
    file.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|e| CatalogError::io("read default catalog initialization marker", e))?;
    if bytes.len() > 1024 {
        return Err(CatalogError::Integrity(
            "default catalog initialization marker exceeds 1 KiB".into(),
        ));
    }
    let state: InitializationState = serde_json::from_slice(&bytes).map_err(|e| {
        CatalogError::Integrity(format!(
            "invalid default catalog initialization marker: {e}"
        ))
    })?;
    Ok(Some(state.catalog_version))
}
// The parent lock protects marker publication. This records upgrade decisions
// only; a marked empty catalog is authoritative after deliberate removals.
fn mark_initialized(root: &Path, version: i64) -> Result<(), CatalogError> {
    if initialization_version(root)? == Some(version) {
        return Ok(());
    }
    let bytes = serde_json::to_vec(&InitializationState {
        catalog_version: version,
    })
    .map_err(|e| CatalogError::Integrity(format!("encode catalog initialization marker: {e}")))?;
    let mut temporary = tempfile::NamedTempFile::new_in(root)
        .map_err(|e| CatalogError::io("stage catalog initialization marker", e))?;
    std::io::Write::write_all(&mut temporary, &bytes)
        .map_err(|e| CatalogError::io("write catalog initialization marker", e))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| CatalogError::io("sync catalog initialization marker", e))?;
    temporary
        .persist(root.join(INITIALIZED))
        .map_err(|e| CatalogError::io("publish catalog initialization marker", e.error))?;
    storage::sync_directory(root)
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpgradeDiagnosticKind {
    #[default]
    Failure,
    Retry,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct UpgradeDiagnostic {
    #[serde(default)]
    kind: UpgradeDiagnosticKind,
    predecessor_version: i64,
    predecessor_path: PathBuf,
    reason: String,
    catalog_version: i64,
}

fn report_diagnostics(
    records: Vec<UpgradeDiagnostic>,
) -> Vec<crate::analyzer::semantic_model::dependency::DependencyPackDiagnostic> {
    use crate::analyzer::semantic_model::dependency::{
        DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    };
    records.into_iter().map(|record| {
            let (code, action) = match record.kind {
                UpgradeDiagnosticKind::Failure => ("catalog.default_upgrade_failed", "Could not migrate"),
                UpgradeDiagnosticKind::Retry => ("catalog.default_upgrade_retried", "Retried migrating"),
            };
            DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Warning,
                code: code.into(), dependency_id: None,
                location: Some(record.predecessor_path.display().to_string()),
                message: format!("{action} catalog v{} at {} to v{}: {}. The upgrade reader did not modify the predecessor; normal pack acquisition can proceed.", record.predecessor_version, record.predecessor_path.display(), record.catalog_version, record.reason),
            }
        }).collect()
}

fn read_report(
    root: &Path,
) -> Result<Vec<crate::analyzer::semantic_model::dependency::DependencyPackDiagnostic>, CatalogError>
{
    let path = root.join(REPORT);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(CatalogError::io("read catalog upgrade report", error)),
    };
    // Treat the sidecar as input: bound decoding even if it was replaced.
    const MAX_REPORT_BYTES: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CatalogError::io("read catalog upgrade report", e))?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(CatalogError::Integrity(
            "catalog upgrade report exceeds 1 MiB".into(),
        ));
    }
    let records: Vec<UpgradeDiagnostic> = serde_json::from_slice(&bytes)
        .map_err(|e| CatalogError::Integrity(format!("invalid catalog upgrade report: {e}")))?;
    Ok(report_diagnostics(records))
}
impl SemanticPackCatalog {
    pub(crate) fn upgrade_diagnostics(
        &self,
    ) -> Result<
        Vec<crate::analyzer::semantic_model::dependency::DependencyPackDiagnostic>,
        CatalogError,
    > {
        let mut diagnostics = self.open_diagnostics.clone();
        match read_report(&self.root) {
            Ok(reports) => diagnostics.extend(reports),
            Err(error) if !diagnostics.is_empty() => {
                use crate::analyzer::semantic_model::dependency::{
                    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
                };
                diagnostics.push(DependencyPackDiagnostic {
                    severity: DependencyPackDiagnosticSeverity::Warning,
                    code: "catalog.default_upgrade_report".into(),
                    dependency_id: None,
                    location: None,
                    message: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
        Ok(diagnostics)
    }
}

fn write_report(root: &Path, records: &[UpgradeDiagnostic]) -> Result<(), CatalogError> {
    if records.is_empty() {
        return Ok(());
    }
    let bytes = serde_json::to_vec(records)
        .map_err(|e| CatalogError::Integrity(format!("encode catalog upgrade report: {e}")))?;
    fs::write(root.join(REPORT), bytes)
        .map_err(|e| CatalogError::io("write catalog upgrade report", e))?;
    fs::OpenOptions::new()
        .write(true)
        .open(root.join(REPORT))
        .and_then(|file| file.sync_all())
        .map_err(|e| CatalogError::io("sync catalog upgrade report", e))?;
    storage::sync_directory(root)
}

fn raw_open(root: &Path, flags: OpenFlags) -> Result<Connection, CatalogError> {
    brokk_bifrost_core::cache_db::disable_sqlite_memory_statistics();
    // SQLITE_OPEN_NOFOLLOW refuses a symlink in any path component, so open
    // through the canonical root (macOS temp roots sit under /var ->
    // /private/var). The database file itself still must not be a link.
    let root = storage::open_read_only_root(root)?;
    let connection =
        Connection::open_with_flags(root.join(DB), flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .map_err(|e| CatalogError::sqlite("open catalog upgrade snapshot", e))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|e| CatalogError::sqlite("configure catalog upgrade timeout", e))?;
    Ok(connection)
}

// No rows in ANY application table except the schema singleton. Its mutation
// counter is a change signal, not user content.
// Preserve sources, receipts, quarantine and future user tables without packs.
fn empty(connection: &Connection) -> Result<bool, CatalogError> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .map_err(|e| CatalogError::sqlite("list catalog state tables", e))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| CatalogError::sqlite("read catalog state tables", e))?;
    for name in names {
        let name = name.map_err(|e| CatalogError::sqlite("read catalog state table", e))?;
        let predicate = if name == "catalog_semantic_state" {
            " WHERE singleton != 1"
        } else {
            ""
        };
        let sql = format!(
            "SELECT EXISTS(SELECT 1 FROM \"{}\"{predicate})",
            name.replace('"', "\"\"")
        );
        if connection
            .query_row(&sql, [], |r| r.get::<_, bool>(0))
            .map_err(|e| CatalogError::sqlite("inspect catalog user state", e))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn has_state(root: &Path) -> Result<bool, CatalogError> {
    if !root.join(DB).exists() {
        return Ok(false);
    }
    match raw_open(root, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => empty(&connection).map(|v| !v),
        // An empty destination can disappear between the optimistic probe
        // and open. Join the parent lock and recheck rather than fail a race.
        Err(_) if !root.join(DB).exists() => Ok(false),
        Err(error) => Err(error),
    }
}
#[derive(Debug)]
enum SnapshotFailure {
    Unusable(CatalogError),
    Environment {
        layer: String,
        error: Box<CatalogError>,
        reports: Vec<UpgradeDiagnostic>,
    },
}
impl From<CatalogError> for SnapshotFailure {
    fn from(error: CatalogError) -> Self {
        Self::Environment {
            layer: "default catalog staging".into(),
            error: Box::new(error),
            reports: Vec::new(),
        }
    }
}
impl SnapshotFailure {
    fn for_predecessor(self, version: i64) -> Self {
        match self {
            Self::Environment {
                layer,
                error,
                reports,
            } => Self::Environment {
                layer: format!("{layer} for predecessor v{version}"),
                error,
                reports,
            },
            other => other,
        }
    }
    fn with_reports(self, mut history: Vec<UpgradeDiagnostic>) -> Self {
        match self {
            Self::Environment {
                layer,
                error,
                mut reports,
            } => {
                history.append(&mut reports);
                Self::Environment {
                    layer,
                    error,
                    reports: history,
                }
            }
            other => other,
        }
    }
}
// Source corruption/data incompatibility is stable. Access and resource
// failures never permanently finalize an empty upgrade.
fn predecessor_failure(error: CatalogError) -> SnapshotFailure {
    use rusqlite::ffi::ErrorCode;
    let unusable = match &error {
        CatalogError::Io { source, .. } => matches!(
            source.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::InvalidData
        ),
        // All other I/O failures are environmental: PermissionDenied,
        // Interrupted, WouldBlock/EAGAIN, TimedOut and raw EIO included.
        CatalogError::Sqlite {
            source: rusqlite::Error::SqliteFailure(code, _),
            ..
        } => !matches!(
            code.code,
            ErrorCode::DatabaseBusy
                | ErrorCode::DatabaseLocked
                | ErrorCode::SystemIoFailure
                | ErrorCode::DiskFull
                | ErrorCode::ReadOnly
                | ErrorCode::CannotOpen
                | ErrorCode::FileLockingProtocolFailed
                | ErrorCode::OutOfMemory
                | ErrorCode::OperationInterrupted
        ),
        CatalogError::Sqlite { .. }
        | CatalogError::Integrity(_)
        | CatalogError::Artifact(_)
        | CatalogError::CatalogTooNew { .. }
        | CatalogError::ReadOnlySchema { .. } => true,
        _ => false,
    };
    if unusable {
        SnapshotFailure::Unusable(error)
    } else {
        SnapshotFailure::Environment {
            layer: "previous catalog".into(),
            error: Box::new(error),
            reports: Vec::new(),
        }
    }
}
#[cfg(test)]
type UpgradeFault = Box<dyn FnMut(&'static str) -> Result<(), CatalogError>>;
#[cfg(test)]
thread_local! {
    static UPGRADE_FAULT: std::cell::RefCell<Option<UpgradeFault>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn upgrade_fault(layer: &'static str) -> Result<(), CatalogError> {
    UPGRADE_FAULT.with(|slot| match slot.borrow_mut().as_mut() {
        Some(hook) => hook(layer),
        None => Ok(()),
    })
}
pub(super) fn deferred_catalog(
    options: CatalogOptions,
    layer: &str,
    error: CatalogError,
    reports: Vec<UpgradeDiagnostic>,
) -> Result<SemanticPackCatalog, CatalogError> {
    use crate::analyzer::semantic_model::dependency::{
        DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    };
    let message = format!(
        "default catalog upgrade deferred: {layer}: {error}; this session uses a temporary catalog and the next start retries"
    );
    eprintln!("catalog.default_upgrade_deferred: {message}");
    #[cfg(test)]
    upgrade_fault("ephemeral")?;
    let mut catalog = SemanticPackCatalog::open_ephemeral(options)?;
    if let Err(report_error) = write_report(&catalog.root, &reports) {
        eprintln!("catalog.default_upgrade_report: {report_error}");
    }
    catalog.open_diagnostics.push(DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Warning,
        code: "catalog.default_upgrade_deferred".into(),
        dependency_id: None,
        location: None,
        message,
    });
    Ok(catalog)
}
pub(super) fn open(
    root: &Path,
    version: i64,
    options: CatalogOptions,
) -> Result<SemanticPackCatalog, CatalogError> {
    match open_durable(root, version, options.clone()) {
        Ok(catalog) => Ok(catalog),
        Err(SnapshotFailure::Unusable(error)) => Err(error),
        Err(SnapshotFailure::Environment {
            layer,
            error,
            reports,
        }) => deferred_catalog(options, &layer, *error, reports),
    }
}

fn open_durable(
    root: &Path,
    version: i64,
    options: CatalogOptions,
) -> Result<SemanticPackCatalog, SnapshotFailure> {
    if root.join(DB).is_file() && initialization_version(root)? == Some(version) {
        return SemanticPackCatalog::open(root, CatalogOpenMode::ReadWrite, options)
            .map_err(SnapshotFailure::from);
    }
    let parent = root.parent().expect("default catalog has a parent");
    // Stable across versions and never renamed with a catalog directory.
    let lock_root = storage::prepare_root(&parent.join("semantic-pack-catalog.locks"))?;
    let _lock = storage::acquire_initialization_lock(&lock_root)?;
    // A pre-fix empty root has no marker: it may be a lost upgrade or a
    // deliberate removal. Those histories are indistinguishable, so only
    // marked roots can promise to preserve an empty selection.
    if initialization_version(root)? != Some(version) && !has_state(root)? {
        upgrade(root, version)?;
    }
    // Legacy non-empty roots also get a marker on their first default open.
    // It prevents later removals from being undone by an older predecessor.
    let catalog = SemanticPackCatalog::open(root, CatalogOpenMode::ReadWrite, options)?;
    mark_initialized(&catalog.root, version)?;
    Ok(catalog)
}
fn upgrade(root: &Path, version: i64) -> Result<(), SnapshotFailure> {
    let parent = root.parent().expect("default catalog has a parent");
    let mut candidates = Vec::new();
    for entry in
        fs::read_dir(parent).map_err(|e| CatalogError::io("list predecessor catalogs", e))?
    {
        let entry = entry.map_err(|e| CatalogError::io("read predecessor catalog", e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(number) = name.strip_prefix("semantic-pack-catalog.v") else {
            continue;
        };
        let Ok(previous) = number.parse::<i64>() else {
            continue;
        };
        if previous > 0
            && previous < version
            && name == format!("semantic-pack-catalog.v{previous}")
        {
            candidates.push((previous, entry.path()));
        }
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
    let mut failures = Vec::new();
    for (previous, source) in candidates {
        let stage = tempfile::Builder::new()
            .prefix(".semantic-pack-upgrade-")
            .tempdir_in(parent)
            .map_err(|e| CatalogError::io("stage catalog upgrade", e))?;
        let mut retries = Vec::new();
        let candidate = initialization_version(&source)
            .map_err(predecessor_failure)
            .and_then(|marker| {
                snapshot(&source, stage.path(), &mut retries)?;
                Ok(marker == Some(previous))
            });
        failures.extend(retries.into_iter().map(|reason| UpgradeDiagnostic {
            kind: UpgradeDiagnosticKind::Retry,
            predecessor_version: previous,
            predecessor_path: source.clone(),
            catalog_version: version,
            reason,
        }));
        match candidate {
            Ok(initialized) => {
                if !has_state(stage.path())? && !initialized {
                    eprintln!(
                        "catalog.default_upgrade_skipped_empty: v{previous} {} contains no installed packs or user state",
                        source.display()
                    );
                    continue;
                }
                write_report(stage.path(), &failures).map_err(|error| {
                    SnapshotFailure::from(error)
                        .for_predecessor(previous)
                        .with_reports(std::mem::take(&mut failures))
                })?;
                mark_initialized(stage.path(), version).map_err(|error| {
                    SnapshotFailure::from(error)
                        .for_predecessor(previous)
                        .with_reports(std::mem::take(&mut failures))
                })?;
                return publish(root, stage).map_err(|e| {
                    SnapshotFailure::from(e)
                        .for_predecessor(previous)
                        .with_reports(failures)
                });
            }
            Err(error @ SnapshotFailure::Environment { .. }) => {
                return Err(error.for_predecessor(previous).with_reports(failures));
            }
            Err(SnapshotFailure::Unusable(error)) => {
                let diagnostic = UpgradeDiagnostic {
                    kind: UpgradeDiagnosticKind::Failure,
                    predecessor_version: previous,
                    predecessor_path: source,
                    catalog_version: version,
                    reason: error.to_string(),
                };
                eprintln!(
                    "catalog.default_upgrade_failed: {diagnostic:?}; old directory untouched"
                );
                failures.push(diagnostic);
            }
        }
    }
    if !failures.is_empty() {
        // A corrupt predecessor must not force manual repair. Publish a fresh
        // catalog plus durable warnings so ordinary acquisition can recover.
        let stage = tempfile::Builder::new()
            .prefix(".semantic-pack-upgrade-")
            .tempdir_in(parent)
            .map_err(|e| CatalogError::io("stage fresh catalog after failed upgrade", e))?;
        let fresh = storage::prepare_root(stage.path())?;
        drop(db::open(&fresh, CatalogOpenMode::ReadWrite)?);
        write_report(stage.path(), &failures)?;
        mark_initialized(stage.path(), version)?;
        publish(root, stage).map_err(|e| SnapshotFailure::from(e).with_reports(failures))?;
    }
    Ok(())
}
enum SnapshotAttempt {
    Complete,
    MissingObject { digest: String, error: CatalogError },
}

#[cfg(test)]
thread_local! {
    static BEFORE_SNAPSHOT_OBJECTS: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

fn snapshot(
    source: &Path,
    target: &Path,
    retries: &mut Vec<String>,
) -> Result<(), SnapshotFailure> {
    assert_ne!(
        source, target,
        "catalog snapshot needs a private staging root"
    );
    loop {
        match snapshot_once(source, target)? {
            SnapshotAttempt::Complete => return Ok(()),
            SnapshotAttempt::MissingObject { digest, error } => {
                // The old read transaction and all stage handles have dropped.
                // GC commits the pack unlink before deleting files. A fresh RO
                // view must prove this transition; still-linked loss is corruption.
                let fresh = raw_open(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(predecessor_failure)?;
                let manifest_link = if has_manifest_objects(&fresh).map_err(predecessor_failure)? {
                    " UNION ALL SELECT 1 FROM catalog_packs WHERE manifest_object_digest=?1"
                } else {
                    ""
                };
                let linked: bool = fresh.query_row(&format!("SELECT EXISTS(SELECT 1 FROM catalog_pack_shards WHERE stored_digest=?1{manifest_link})"), [&digest], |r| r.get(0))
                    .map_err(|e| CatalogError::sqlite("prove concurrent catalog object unlink", e))?;
                if linked {
                    return Err(SnapshotFailure::Unusable(error));
                }
                // Discard every byte from the failed attempt, preserving only
                // the private temp directory's restrictive permissions.
                for entry in fs::read_dir(target)
                    .map_err(|e| CatalogError::io("reset catalog snapshot", e))?
                {
                    let entry =
                        entry.map_err(|e| CatalogError::io("inspect failed snapshot", e))?;
                    if entry
                        .file_type()
                        .map_err(|e| CatalogError::io("inspect failed snapshot entry", e))?
                        .is_dir()
                    {
                        fs::remove_dir_all(entry.path()).map_err(|e| {
                            CatalogError::io("discard failed snapshot directory", e)
                        })?;
                    } else {
                        fs::remove_file(entry.path())
                            .map_err(|e| CatalogError::io("discard failed snapshot file", e))?;
                    }
                }
                let reason = format!("object {digest} unlinked since snapshot");
                eprintln!(
                    "catalog.default_upgrade_retried: predecessor={source:?} reason={reason:?}"
                );
                retries.push(reason);
                // No retry limit: each attempt requires a new proven unlink.
            }
        }
    }
}

fn snapshot_once(source: &Path, target: &Path) -> Result<SnapshotAttempt, SnapshotFailure> {
    // db::open and raw_open use SQLITE_OPEN_NOFOLLOW; keep the canonical root.
    let target = &storage::prepare_root(target)?;
    #[cfg(test)]
    upgrade_fault("source").map_err(predecessor_failure)?;
    fs::metadata(source.join(DB)).map_err(|e| {
        predecessor_failure(CatalogError::io("inspect previous catalog database", e))
    })?;
    let mut source_db =
        raw_open(source, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(predecessor_failure)?;
    // Backup includes committed WAL pages; copying catalog.db alone does not.
    // The predecessor is byte-unchanged except the SQLite coordination files
    // any reader creates: SQLite-owned -wal (header only) and -shm
    // (wal-index/read marks). Never change journal mode, checkpoint, or use
    // immutable=1 here. A pre-existing WAL is read without changing frames.
    let transaction = source_db
        .transaction()
        .map_err(|e| predecessor_failure(CatalogError::sqlite("pin predecessor snapshot", e)))?;
    let _: i64 = transaction
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| predecessor_failure(CatalogError::sqlite("read predecessor version", e)))?;
    let mut destination = Connection::open(target.join(DB))
        .map_err(|e| CatalogError::sqlite("create catalog snapshot", e))?;
    {
        let backup = rusqlite::backup::Backup::new(&transaction, &mut destination)
            .map_err(|e| predecessor_failure(CatalogError::sqlite("start catalog snapshot", e)))?;
        backup
            .run_to_completion(128, Duration::from_millis(5), None)
            .map_err(|e| predecessor_failure(CatalogError::sqlite("copy catalog snapshot", e)))?;
    }
    #[cfg(test)]
    upgrade_fault("stage-write")?;
    discard_rebuildable_state(&destination).map_err(predecessor_failure)?;
    let mut statement = destination
        .prepare("SELECT relative_path, stored_digest, stored_size FROM catalog_objects")
        .map_err(|e| predecessor_failure(CatalogError::sqlite("list snapshot objects", e)))?;
    let objects = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| predecessor_failure(CatalogError::sqlite("read snapshot objects", e)))?;
    #[cfg(test)]
    BEFORE_SNAPSHOT_OBJECTS.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook();
        }
    });
    for object in objects {
        let (relative, digest, size) = object
            .map_err(|e| predecessor_failure(CatalogError::sqlite("read snapshot object", e)))?;
        let bytes = match storage::read(source, &relative, &digest, size) {
            Ok(bytes) => bytes,
            Err(error) if matches!(&error, CatalogError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(SnapshotAttempt::MissingObject { digest, error });
            }
            Err(error) => return Err(predecessor_failure(error)),
        };
        storage::publish(target, &digest, &bytes)?;
    }
    drop(statement);
    drop(destination);
    transaction.commit().map_err(|e| {
        predecessor_failure(CatalogError::sqlite("release predecessor snapshot", e))
    })?;
    drop(
        db::open(target, CatalogOpenMode::ReadWrite).map_err(|error| match error {
            CatalogError::Io { .. } => SnapshotFailure::from(error),
            other => predecessor_failure(other),
        })?,
    );
    fs::OpenOptions::new()
        .write(true)
        .open(target.join(DB))
        .and_then(|file| file.sync_all())
        .map_err(|e| CatalogError::io("sync migrated catalog snapshot", e))?;
    storage::sync_directory(target)?;
    let verification = raw_open(target, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    check_integrity(&verification).map_err(predecessor_failure)?;
    drop(verification);
    verify_catalog(target)?;
    Ok(SnapshotAttempt::Complete)
}
fn tables(connection: &Connection) -> Result<Vec<String>, CatalogError> {
    connection.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .and_then(|mut statement| statement.query_map([], |r| r.get(0))?.collect())
        .map_err(|e| CatalogError::sqlite("list catalog import tables", e))
}
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn has_manifest_objects(connection: &Connection) -> Result<bool, CatalogError> {
    let result = connection
        .prepare("PRAGMA table_info(catalog_packs)")
        .and_then(|mut statement| {
            statement
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(|e| CatalogError::sqlite("inspect snapshot manifest storage", e))?
        .iter()
        .any(|name| name == "manifest_object_digest");
    Ok(result)
}
fn discard_rebuildable_state(connection: &Connection) -> Result<(), CatalogError> {
    let names = tables(connection)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|e| CatalogError::sqlite("enable snapshot foreign keys", e))?;
    // Generated packs with no durable source, pin or activation can be
    // collected by the old process despite our WAL snapshot. They are caches.
    let mut protected = vec!["EXISTS(SELECT 1 FROM catalog_sources s WHERE s.manifest_digest=catalog_packs.manifest_digest AND s.source_kind <> 'generated')".to_owned()];
    for table in ["catalog_pins", "catalog_activations"] {
        if names.iter().any(|name| name == table) {
            protected.push(format!(
                "EXISTS(SELECT 1 FROM {} p WHERE p.manifest_digest=catalog_packs.manifest_digest)",
                quoted(table)
            ));
        }
    }
    connection
        .execute(
            &format!(
                "DELETE FROM catalog_packs WHERE NOT ({})",
                protected.join(" OR ")
            ),
            [],
        )
        .map_err(|e| CatalogError::sqlite("discard rebuildable snapshot packs", e))?;
    // Pack deletion cascades to generated productions and source identities.
    // Keep those rows, and catalog_sources, for pinned or activated packs:
    // their retained source is required to select the protected pack again.
    let manifest_objects = has_manifest_objects(connection)?;
    let manifests = if manifest_objects {
        " OR EXISTS(SELECT 1 FROM catalog_packs p WHERE p.manifest_object_digest=catalog_objects.stored_digest)"
    } else {
        ""
    };
    connection.execute(&format!("DELETE FROM catalog_objects WHERE NOT (EXISTS(SELECT 1 FROM catalog_pack_shards s WHERE s.stored_digest=catalog_objects.stored_digest){manifests})"), []).map_err(|e| CatalogError::sqlite("discard orphan snapshot metadata", e))?;
    Ok(())
}
fn check_integrity(connection: &Connection) -> Result<(), CatalogError> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|e| CatalogError::sqlite("check imported foreign keys", e))?;
    let violations = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        .map_err(|e| CatalogError::sqlite("read imported foreign key check", e))?;
    if !violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog import foreign key violations: {violations:?}"
        )));
    }
    Ok(())
}
fn verify_catalog(root: &Path) -> Result<(), CatalogError> {
    let connection = raw_open(root, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    check_integrity(&connection)?;
    let mut statement = connection
        .prepare("SELECT relative_path, stored_digest, stored_size FROM catalog_objects")
        .map_err(|e| CatalogError::sqlite("verify snapshot objects", e))?;
    let objects = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| CatalogError::sqlite("read snapshot verification objects", e))?;
    for object in objects {
        let (relative, digest, size) =
            object.map_err(|e| CatalogError::sqlite("read snapshot verification object", e))?;
        storage::verify_existing(root, Path::new(&relative), &digest, size)?;
    }
    Ok(())
}
fn copy_objects(source: &Path, target: &Path) -> Result<(), CatalogError> {
    let connection = raw_open(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection
        .prepare("SELECT relative_path, stored_digest, stored_size FROM catalog_objects")
        .map_err(|e| CatalogError::sqlite("list imported objects", e))?;
    let objects = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })
        .map_err(|e| CatalogError::sqlite("read imported objects", e))?;
    for object in objects {
        let (relative, digest, size) =
            object.map_err(|e| CatalogError::sqlite("read imported object", e))?;
        storage::publish(
            target,
            &digest,
            &storage::read(source, &relative, &digest, size)?,
        )?;
    }
    Ok(())
}
fn import_rows(transaction: &Transaction<'_>, stage: &Path) -> Result<(), CatalogError> {
    // The attached database inherits the destination's SQLITE_OPEN_NOFOLLOW.
    let stage = storage::open_read_only_root(stage)?;
    transaction
        .execute(
            "ATTACH DATABASE ?1 AS upgrade_source",
            [stage.join(DB).to_string_lossy().as_ref()],
        )
        .map_err(|e| CatalogError::sqlite("attach staged catalog", e))?;
    let mut remaining = tables(transaction)?
        .into_iter()
        .filter(|name| name != "catalog_semantic_state")
        .collect::<Vec<_>>();
    let mut done = HashSet::new();
    while !remaining.is_empty() {
        let mut progress = false;
        for name in remaining.clone() {
            let mut statement = transaction
                .prepare(&format!("PRAGMA foreign_key_list({})", quoted(&name)))
                .map_err(|e| CatalogError::sqlite("order catalog import", e))?;
            let dependencies = statement
                .query_map([], |r| r.get::<_, String>(2))
                .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
                .map_err(|e| CatalogError::sqlite("read import dependencies", e))?;
            if dependencies.iter().any(|dependency| {
                dependency != &name
                    && dependency != "catalog_semantic_state"
                    && !done.contains(dependency)
            }) {
                continue;
            }
            let columns = transaction
                .prepare(&format!("PRAGMA table_info({})", quoted(&name)))
                .and_then(|mut statement| {
                    statement
                        .query_map([], |r| r.get::<_, String>(1))?
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .map_err(|e| CatalogError::sqlite("read writable import columns", e))?;
            // table_info excludes generated columns; SELECT * includes them.
            let columns = columns
                .iter()
                .map(|column| quoted(column))
                .collect::<Vec<_>>()
                .join(",");
            transaction
                .execute(
                    &format!(
                        "INSERT INTO main.{} ({columns}) SELECT {columns} FROM upgrade_source.{}",
                        quoted(&name),
                        quoted(&name)
                    ),
                    [],
                )
                .map_err(|e| CatalogError::sqlite("import staged catalog rows", e))?;
            done.insert(name.clone());
            remaining.retain(|value| value != &name);
            progress = true;
        }
        if !progress {
            return Err(CatalogError::Integrity(format!(
                "cyclic catalog import dependencies: {remaining:?}"
            )));
        }
    }
    // Keep the destination singleton: INSERT triggers advance its epoch, so
    // live readers see a strictly newer change signal after the transaction.
    check_integrity(transaction)
}
fn import_existing(root: &Path, stage: &Path) -> Result<(), CatalogError> {
    let root = storage::prepare_root(root)?;
    let _lock = storage::acquire_initialization_lock(&root)?;
    let mut destination = db::open(&root, CatalogOpenMode::ReadWrite)?;
    copy_objects(stage, &root)?;
    let transaction = destination
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(|e| CatalogError::sqlite("lock empty catalog for import", e))?;
    if !empty(&transaction)? {
        return Ok(());
    }
    // A live destination GC could collect the pre-published orphan files.
    // Republish under the SQLite writer lock, which also excludes its GC.
    copy_objects(stage, &root)?;
    import_rows(&transaction, stage)?;
    // Every retained row now has a hash-verified object in the stable root.
    if stage.join(REPORT).exists() {
        let bytes = fs::read(stage.join(REPORT))
            .map_err(|e| CatalogError::io("read staged upgrade report", e))?;
        let mut report = tempfile::NamedTempFile::new_in(&root)
            .map_err(|e| CatalogError::io("stage imported upgrade report", e))?;
        std::io::Write::write_all(&mut report, &bytes)
            .map_err(|e| CatalogError::io("write imported upgrade report", e))?;
        report
            .as_file()
            .sync_all()
            .map_err(|e| CatalogError::io("sync imported upgrade report", e))?;
        report
            .persist(root.join(REPORT))
            .map_err(|e| CatalogError::io("publish imported upgrade report", e.error))?;
    }
    transaction
        .commit()
        .map_err(|e| CatalogError::sqlite("commit catalog import", e))?;
    // A crash before this marker is safe: a populated committed root is
    // recognized as legacy non-empty and marked on the next default open.
    if let Some(version) = initialization_version(stage)? {
        mark_initialized(&root, version)?;
    }
    storage::sync_directory(&root)?;
    Ok(())
}
fn publish(root: &Path, stage: TempDir) -> Result<(), CatalogError> {
    if root.exists() {
        return import_existing(root, stage.path());
    }
    // With no directory, no process holds its DB. A crash leaves either no
    // catalog or the complete, verified snapshot after this atomic rename.
    verify_catalog(stage.path())?;
    fs::rename(stage.path(), root).map_err(|e| CatalogError::io("publish upgraded catalog", e))?;
    storage::sync_directory(root.parent().expect("default catalog has a parent"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn seed(parent: &Path) -> PathBuf {
        let root = parent.join("semantic-pack-catalog.v29");
        let catalog =
            SemanticPackCatalog::open(&root, CatalogOpenMode::ReadWrite, CatalogOptions::default())
                .unwrap();
        let pack = super::super::go_extraction_support_22::callable_pack();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "offline-custom-pack".into(),
                },
            )
            .unwrap();
        drop(catalog);
        // The v30 change only adds validation census columns. Recreate the
        // actual v29 shape, so ordered migration 30 must run on the copy.
        let db = Connection::open(root.join(DB)).unwrap();
        db.execute_batch("DROP TABLE catalog_shard_validations; CREATE TABLE catalog_shard_validations(manifest_digest TEXT NOT NULL, shard_id TEXT NOT NULL, validation_version INTEGER NOT NULL, limits_sha256 TEXT NOT NULL, PRIMARY KEY(manifest_digest,shard_id,validation_version,limits_sha256)) WITHOUT ROWID; PRAGMA user_version=29;").unwrap();
        drop(db);
        root
    }
    #[test]
    #[hardwon("#12422: a populated schema upgrade can leave dependent semantic rows dangling")]
    fn populated_upgrade_and_import_keep_dependent_rows_consistent() {
        fn no_foreign_key_violations(connection: &Connection, step: &str) {
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0,
                "{step}"
            );
        }
        fn derived_rows(connection: &Connection, shard: i64) -> (i64, i64) {
            let families = connection
                .query_row(
                    "SELECT count(*) FROM catalog_semantic_payload_families WHERE shard_key=?1",
                    [shard],
                    |row| row.get(0),
                )
                .unwrap();
            let summaries = connection.query_row("SELECT count(*) FROM catalog_procedure_summaries WHERE shard_key=?1 AND record_id='preserved-procedure'", [shard], |row| row.get(0)).unwrap();
            (families, summaries)
        }
        for existing in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let source = seed(parent.path());
            let connection = raw_open(&source, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
            connection.execute_batch("PRAGMA foreign_keys=ON;
                INSERT OR IGNORE INTO catalog_semantic_rows_indexed_shards(manifest_digest,shard_id,index_version)
                SELECT manifest_digest,shard_id,4 FROM catalog_pack_shards LIMIT 1;").unwrap();
            let shard: i64 = connection
                .query_row(
                    "SELECT shard_key FROM catalog_semantic_rows_indexed_shards LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            connection.execute("INSERT OR IGNORE INTO catalog_semantic_payload_families(shard_key,family) VALUES(?1,'callable_values')", [shard]).unwrap();
            connection.execute("INSERT INTO catalog_procedure_summaries(shard_key,language,target_path,target_symbol,has_receiver,declared_arity,variadic,minimum_actual_count,record_json) VALUES(?1,'go','fixture.go','fixture',0,0,0,0,'{\"id\":\"preserved-procedure\"}')", [shard]).unwrap();
            no_foreign_key_violations(&connection, "populated predecessor before migration");
            let original = derived_rows(&connection, shard);
            assert!(original.0 > 0 && original.1 > 0);
            drop(connection);

            let stage = tempfile::tempdir_in(parent.path()).unwrap();
            snapshot(&source, stage.path(), &mut Vec::new()).unwrap();
            let staged = raw_open(stage.path(), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            no_foreign_key_violations(&staged, "after existing ordered migrations on the copy");
            // Ordered migrations may invalidate derived caches. Import must
            // preserve their resulting consistent state, not resurrect rows.
            let migrated = derived_rows(&staged, shard);
            assert_eq!(
                staged
                    .query_row("SELECT count(*) FROM catalog_packs", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            drop(staged);
            let target = parent.path().join("semantic-pack-catalog.v30");
            if existing {
                drop(
                    SemanticPackCatalog::open(
                        &target,
                        CatalogOpenMode::ReadWrite,
                        CatalogOptions::default(),
                    )
                    .unwrap(),
                );
            }
            publish(&target, stage).unwrap();
            // db::open takes a canonical root; the temp parent may be a link.
            let destination = db::open(
                &fs::canonicalize(&target).unwrap(),
                CatalogOpenMode::ReadWrite,
            )
            .unwrap();
            no_foreign_key_violations(
                &destination,
                "after atomic publication or in-place import commits",
            );
            assert_eq!(derived_rows(&destination, shard), migrated);
            assert_eq!(
                destination
                    .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            destination
                .execute(
                    "DELETE FROM catalog_semantic_rows_indexed_shards WHERE shard_key=?1",
                    [shard],
                )
                .unwrap();
            assert_eq!(
                derived_rows(&destination, shard),
                (0, 0),
                "dependent caches cascade with their parent"
            );
            no_foreign_key_violations(&destination, "after imported parent deletion");
            drop(destination);
            let predecessor = raw_open(&source, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            no_foreign_key_violations(&predecessor, "predecessor remains consistent");
            assert_eq!(
                derived_rows(&predecessor, shard),
                original,
                "copy and destination cascade never modify the predecessor"
            );
        }
    }

    fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut directories = vec![root.to_owned()];
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    directories.push(path);
                } else {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_owned(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        files
    }
    fn assert_installed(catalog: &SemanticPackCatalog) {
        let db = catalog.connection.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM catalog_packs WHERE state='verified'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let mut statement = db
            .prepare("SELECT relative_path, stored_digest, stored_size FROM catalog_objects")
            .unwrap();
        for row in statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })
            .unwrap()
        {
            let (relative, digest, size) = row.unwrap();
            storage::read(&catalog.root, &relative, &digest, size).unwrap();
        }
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            CATALOG_SCHEMA_VERSION
        );
        drop(statement);
        drop(db);
        let pack = super::super::go_extraction_support_22::callable_pack();
        let result = catalog
            .query_callable_values(
                &super::super::go_extraction_support_22::query(
                    &pack,
                    CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                ),
                CatalogCallableValuesQueryLimits { max_records: 4 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            result.facts.len(),
            2,
            "migrated offline pack remains queryable"
        );
    }
    #[test]
    #[hardwon("#12422: default catalog version changes lost offline installed packs")]
    fn upgrade_preserves_packs_and_source_bytes_with_empty_destination() {
        for existing in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let source = seed(parent.path());
            let before = files(&source);
            let modified = fs::metadata(source.join(DB)).unwrap().modified().unwrap();
            let target = parent.path().join("semantic-pack-catalog.v30");
            if existing {
                drop(
                    SemanticPackCatalog::open(
                        &target,
                        CatalogOpenMode::ReadWrite,
                        CatalogOptions::default(),
                    )
                    .unwrap(),
                );
            }
            let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
            assert_installed(&catalog);
            let after = files(&source);
            for (path, bytes) in &before {
                if path == Path::new("catalog.db-shm") {
                    continue;
                }
                assert_eq!(
                    after.get(path),
                    Some(bytes),
                    "source file changed: {}",
                    path.display()
                );
            }
            for (path, bytes) in &after {
                if !before.contains_key(path) {
                    assert!(
                        path == Path::new("catalog.db-wal") || path == Path::new("catalog.db-shm")
                    );
                    if path == Path::new("catalog.db-wal") {
                        assert!(bytes.len() <= 32, "reader-created WAL contains frames");
                    }
                }
            }
            assert_eq!(
                fs::metadata(source.join(DB)).unwrap().modified().unwrap(),
                modified
            );
            let reader = raw_open(&source, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let write = reader
                .execute_batch("CREATE TABLE must_not_write(value TEXT)")
                .unwrap_err();
            assert!(
                matches!(write, rusqlite::Error::SqliteFailure(ref error, _) if error.code == rusqlite::ffi::ErrorCode::ReadOnly)
            );
            drop(reader);
        }
    }
    // macOS temp roots reproduce this through /var -> /private/var; an
    // explicit link pins it on every Unix host.
    #[cfg(unix)]
    #[test]
    #[hardwon("#4604: NOFOLLOW upgrade opens refused a catalog parent reached through a symlink")]
    fn upgrade_through_symlinked_parent_preserves_packs() {
        for existing in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let real = temp.path().join("real");
            fs::create_dir(&real).unwrap();
            let parent = temp.path().join("link");
            std::os::unix::fs::symlink(&real, &parent).unwrap();
            seed(&parent);
            let target = parent.join("semantic-pack-catalog.v30");
            if existing {
                // Import into an existing root ATTACHes the staged copy.
                drop(
                    SemanticPackCatalog::open(
                        &target,
                        CatalogOpenMode::ReadWrite,
                        CatalogOptions::default(),
                    )
                    .unwrap(),
                );
            }
            assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
        }
    }
    #[test]
    #[hardwon("#12422: concurrent default catalog upgrade must publish one installed set")]
    fn concurrent_process_absent_and_empty_opens() {
        for existing in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            seed(parent.path());
            let target = parent.path().join("semantic-pack-catalog.v30");
            if existing {
                drop(
                    SemanticPackCatalog::open(
                        &target,
                        CatalogOpenMode::ReadWrite,
                        CatalogOptions::default(),
                    )
                    .unwrap(),
                );
            }
            let child_name = format!(
                "{}::upgrade_child",
                module_path!().split_once("::").unwrap().1
            );
            let mut children = Vec::new();
            for id in ["first", "second"] {
                children.push(
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", &child_name, "--nocapture"])
                        .env("BIFROST_TEST_UPGRADE_ROOT", &target)
                        .env("BIFROST_TEST_UPGRADE_ID", id)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap(),
                );
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            while !parent.path().join("first.ready").exists()
                || !parent.path().join("second.ready").exists()
            {
                assert!(Instant::now() < deadline, "upgrade children did not start");
                std::thread::sleep(Duration::from_millis(5));
            }
            fs::write(parent.path().join("start"), []).unwrap();
            for child in children {
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
        }
    }
    #[test]
    fn upgrade_child() {
        let Some(root) = std::env::var_os("BIFROST_TEST_UPGRADE_ROOT") else {
            return;
        };
        let target = PathBuf::from(root);
        let parent = target.parent().unwrap();
        let id = std::env::var("BIFROST_TEST_UPGRADE_ID").unwrap();
        fs::write(parent.join(format!("{id}.ready")), []).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !parent.join("start").exists() {
            assert!(
                Instant::now() < deadline,
                "parent did not release upgrade barrier"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
    }
    #[test]
    #[hardwon("#12422: failed predecessor must not silently create an empty catalog")]
    fn failed_predecessor_recovers_with_durable_typed_warning() {
        let parent = tempfile::tempdir().unwrap();
        let source = parent.path().join("semantic-pack-catalog.v29");
        fs::create_dir(&source).unwrap();
        fs::write(source.join(DB), b"invalid sqlite").unwrap();
        let target = parent.path().join("semantic-pack-catalog.v30");
        let before = files(&source);
        let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
        let warnings = catalog.upgrade_diagnostics().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "catalog.default_upgrade_failed");
        // Stand in for normal acquisition without network access: install the
        // custom fixture through the same catalog installation API.
        catalog
            .install(
                &super::super::go_extraction_support_22::callable_pack(),
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "normal-acquisition".into(),
                },
            )
            .unwrap();
        assert_installed(&catalog);
        drop(catalog);
        let reopened = open(&target, 30, CatalogOptions::default()).unwrap();
        assert_eq!(reopened.upgrade_diagnostics().unwrap(), warnings);
        let activated = crate::analyzer::semantic_model::dependency::prepare_compatible_installed_semantic_packs(&reopened, &[], &crate::analyzer::semantic_model::dependency::DependencyPackLimits::default(), None);
        assert_eq!(
            activated
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "catalog.default_upgrade_failed")
                .count(),
            1,
            "later activation surfaces the durable warning"
        );
        assert_eq!(files(&source), before);
    }
    #[test]
    #[hardwon("#12422: an interrupted catalog import must roll back and retry")]
    fn crash_mid_import_retries_from_predecessor() {
        for committed in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let source = seed(parent.path());
            let target = parent.path().join("semantic-pack-catalog.v30");
            drop(
                SemanticPackCatalog::open(
                    &target,
                    CatalogOpenMode::ReadWrite,
                    CatalogOptions::default(),
                )
                .unwrap(),
            );
            let stage = tempfile::tempdir_in(parent.path()).unwrap();
            snapshot(&source, stage.path(), &mut Vec::new()).unwrap();
            mark_initialized(stage.path(), 30).unwrap();
            copy_objects(stage.path(), &target).unwrap();
            let child_name = format!(
                "{}::import_crash_child",
                module_path!().split_once("::").unwrap().1
            );
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &child_name, "--nocapture"])
                .env("BIFROST_TEST_CRASH_ROOT", &target)
                .env("BIFROST_TEST_CRASH_STAGE", stage.path())
                .env(
                    "BIFROST_TEST_CRASH_AFTER_COMMIT",
                    if committed { "1" } else { "0" },
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(77),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(has_state(&target).unwrap(), committed);
            assert_eq!(initialization_version(&target).unwrap(), None);
            assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
            assert_eq!(initialization_version(&target).unwrap(), Some(30));
        }
    }
    #[test]
    fn import_crash_child() {
        let Some(root) = std::env::var_os("BIFROST_TEST_CRASH_ROOT") else {
            return;
        };
        let stage = PathBuf::from(std::env::var_os("BIFROST_TEST_CRASH_STAGE").unwrap());
        // db::open takes a canonical root; the temp parent may be a link.
        let mut connection = db::open(
            &fs::canonicalize(&root).unwrap(),
            CatalogOpenMode::ReadWrite,
        )
        .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .unwrap();
        import_rows(&transaction, &stage).unwrap();
        if std::env::var("BIFROST_TEST_CRASH_AFTER_COMMIT").as_deref() == Ok("1") {
            transaction.commit().unwrap();
        }
        // Abrupt exit skips rollback, or marker publication after COMMIT.
        std::process::exit(77);
    }
    #[test]
    fn live_empty_catalog_keeps_one_database_and_monotonic_epoch() {
        let parent = tempfile::tempdir().unwrap();
        seed(parent.path());
        let target = parent.path().join("semantic-pack-catalog.v30");
        let live = SemanticPackCatalog::open(
            &target,
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        live.connection
            .lock()
            .unwrap()
            .execute("UPDATE catalog_semantic_state SET mutation_epoch=10000", [])
            .unwrap();
        let before: i64 = live
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT mutation_epoch FROM catalog_semantic_state",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let current = open(&target, 30, CatalogOptions::default()).unwrap();
        assert_installed(&live);
        let after: i64 = live
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT mutation_epoch FROM catalog_semantic_state",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(after > before, "live epoch cache detects imported state");
        let mut authored: crate::analyzer::semantic_model::AuthoredSemanticModelPack =
            serde_json::from_slice(super::super::go_extraction_support_22::DECLARATIONS).unwrap();
        authored.schema_version = 10;
        authored.compatibility.bifrost = None;
        authored.pack_id = "late.custom".into();
        let pack = crate::analyzer::semantic_model::compile_pack(
            &authored,
            &crate::analyzer::semantic_model::CompilerOptions::default(),
        )
        .unwrap();
        live.install(
            &pack,
            &DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "late-install".into(),
            },
        )
        .unwrap();
        let count: i64 = current
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM catalog_packs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "late install reaches the same published DB");
        verify_catalog(&target).unwrap();
    }
    #[test]
    fn empty_predecessor_and_missing_gc_orphan_do_not_hide_installed_packs() {
        let parent = tempfile::tempdir().unwrap();
        let source = seed(parent.path());
        let older = parent.path().join("semantic-pack-catalog.v28");
        fs::rename(&source, &older).unwrap();
        drop(
            SemanticPackCatalog::open(
                &source,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap(),
        );
        let connection = Connection::open(older.join(DB)).unwrap();
        let digest = "f".repeat(64);
        connection
            .execute(
                "INSERT INTO catalog_objects VALUES(?1,?2,1,1,'raw',1)",
                params![
                    digest,
                    storage::relative_object_path(&digest).to_string_lossy()
                ],
            )
            .unwrap();
        drop(connection);
        let target = parent.path().join("semantic-pack-catalog.v30");
        let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
        assert_installed(&catalog);
        let count: i64 = catalog
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM catalog_objects WHERE stored_digest=?1",
                [&digest],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "collected orphan metadata is discarded only in stage"
        );
        let old = raw_open(&older, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(
            old.query_row(
                "SELECT count(*) FROM catalog_objects WHERE stored_digest=?1",
                [&digest],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
    #[test]
    fn user_state_without_packs_is_never_replaced() {
        let parent = tempfile::tempdir().unwrap();
        seed(parent.path());
        let target = parent.path().join("semantic-pack-catalog.v30");
        drop(
            SemanticPackCatalog::open(
                &target,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap(),
        );
        let connection = Connection::open(target.join(DB)).unwrap();
        connection.execute_batch("CREATE TABLE custom_user_state(value TEXT); INSERT INTO custom_user_state VALUES('keep');").unwrap();
        drop(connection);
        let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT value FROM custom_user_state", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "keep"
        );
        assert_eq!(initialization_version(&target).unwrap(), Some(30));
    }
    #[test]
    fn override_parent_and_live_wal_snapshot_skip_unusable_newest() {
        let parent = tempfile::tempdir().unwrap();
        let source = seed(parent.path());
        let live = Connection::open(source.join(DB)).unwrap();
        live.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE wal_state(value TEXT); INSERT INTO wal_state VALUES('committed WAL');").unwrap();
        assert!(source.join("catalog.db-wal").exists());
        let source_before = files(&source);
        let database_before = fs::read(source.join(DB)).unwrap();
        let wal_before = fs::read(source.join("catalog.db-wal")).unwrap();
        let unusable = parent.path().join("semantic-pack-catalog.v30");
        fs::create_dir(&unusable).unwrap();
        fs::write(unusable.join(DB), b"bad sqlite").unwrap();
        let root = default_semantic_pack_catalog_root_with_override(
            Path::new("ignored-workspace"),
            Some(parent.path().as_os_str().to_owned()),
        );
        let target = root.with_file_name("semantic-pack-catalog.v31");
        let catalog = open(&target, 31, CatalogOptions::default()).unwrap();
        assert_installed(&catalog);
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT value FROM wal_state", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "committed WAL"
        );
        assert_eq!(fs::read(source.join(DB)).unwrap(), database_before);
        assert_eq!(fs::read(source.join("catalog.db-wal")).unwrap(), wal_before);
        let source_after = files(&source);
        for (path, bytes) in &source_before {
            if path != Path::new("catalog.db-shm") {
                assert_eq!(
                    source_after.get(path),
                    Some(bytes),
                    "source changed: {}",
                    path.display()
                );
            }
        }
        assert_eq!(
            source_before.keys().collect::<Vec<_>>(),
            source_after.keys().collect::<Vec<_>>()
        );
        live.execute(
            "INSERT INTO wal_state VALUES('old binary still writes')",
            [],
        )
        .unwrap();
        assert_eq!(
            live.query_row("SELECT count(*) FROM wal_state", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        let reopened_old = Connection::open(source.join(DB)).unwrap();
        reopened_old
            .execute("INSERT INTO wal_state VALUES('old binary reopened')", [])
            .unwrap();
        assert_eq!(
            reopened_old
                .query_row("SELECT count(*) FROM wal_state", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            catalog
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM wal_state", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "old writes stay in predecessor"
        );
        assert_eq!(catalog.upgrade_diagnostics().unwrap().len(), 1);
        assert!(source.exists());
    }
    #[test]
    #[hardwon("#12422: migration removed generated sources for pinned or active packs")]
    fn protected_generated_packs_keep_selectable_sources_and_cache_bindings() {
        for protection in ["pin", "activation"] {
            let parent = tempfile::tempdir().unwrap();
            let source = seed(parent.path());
            let connection = Connection::open(source.join(DB)).unwrap();
            let digest: String = connection
                .query_row("SELECT manifest_digest FROM catalog_packs", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let pack = super::super::go_extraction_support_22::callable_pack();
            let key = GeneratedProductionKey::new(
                "c".repeat(64),
                &pack.manifest.producer.name,
                &pack.manifest.producer.version,
                pack.manifest.schema_version,
            )
            .unwrap();
            connection
                .execute(
                    "UPDATE catalog_sources SET source_kind='generated', source_id=?1",
                    [key.source_id()],
                )
                .unwrap();
            if protection == "pin" {
                connection
                    .execute(
                        "INSERT INTO catalog_pins VALUES(?1,'user-pin',1)",
                        [&digest],
                    )
                    .unwrap();
            } else {
                connection.execute("INSERT INTO catalog_activations VALUES('user-scope',?1,?2,'generated',?3,1)", params!["a".repeat(64),digest,key.source_id()]).unwrap();
            }
            connection.execute("INSERT INTO catalog_generated_productions(production_digest,input_digest,producer_name,producer_version,schema_version,manifest_digest,created_at,generated_cache_version) VALUES(?1,?2,?3,?4,?5,?6,1,?7)", params![key.production_digest(),key.input_digest(),key.producer_name(),key.producer_version(),pack.manifest.schema_version,digest,GENERATED_PRODUCTION_CACHE_VERSION]).unwrap();
            connection
                .execute(
                    "INSERT INTO catalog_generated_source_identities VALUES(?1,?2,?3,?4,?5,?6,1)",
                    params![
                        "d".repeat(64),
                        key.producer_name(),
                        key.producer_version(),
                        pack.manifest.schema_version,
                        GENERATED_PRODUCTION_CACHE_VERSION,
                        key.production_digest()
                    ],
                )
                .unwrap();
            drop(connection);
            let target = parent.path().join("semantic-pack-catalog.v30");
            let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
            let candidates = catalog
                .candidates(&SemanticPackSelectorQuery {
                    language: "java".into(),
                    ecosystem: "maven".into(),
                    package: Some(CatalogCoordinate {
                        name: "com.acme:widget".into(),
                        version: Some("1.2.0".parse().unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "jdk".into(),
                        version: Some("17.0.0".parse().unwrap()),
                    }),
                    target: Some("jvm".into()),
                    configuration: Some("release".into()),
                    artifact_sha256: None,
                    bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                })
                .unwrap();
            assert_eq!(
                candidates.len(),
                1,
                "{protection}: protected generated source remains selectable"
            );
            catalog.load_decoded_for_test(&candidates[0]).unwrap();
            assert_installed(&catalog);
            assert!(catalog.generated_production(&key).unwrap().is_some());
            let db = catalog.connection.lock().unwrap();
            for table in [
                "catalog_generated_productions",
                "catalog_generated_source_identities",
            ] {
                assert_eq!(
                    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    1,
                    "{protection}: retained generated binding {table}"
                );
            }
        }
    }
    #[test]
    #[hardwon("#12422: an intentionally emptied default catalog resurrected predecessor packs")]
    fn marked_empty_catalog_preserves_removals_here_and_on_next_upgrade() {
        let parent = tempfile::tempdir().unwrap();
        seed(parent.path());
        let target = parent.path().join("semantic-pack-catalog.v30");
        let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
        catalog
            .remove_source(&DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "offline-custom-pack".into(),
            })
            .unwrap();
        let gc = catalog
            .garbage_collect(&CatalogGcOptions {
                minimum_age: Duration::ZERO,
                ..CatalogGcOptions::default()
            })
            .unwrap();
        assert_eq!(gc.pruned_packs, 1);
        drop(catalog);
        assert!(!has_state(&target).unwrap());
        drop(open(&target, 30, CatalogOptions::default()).unwrap());
        assert!(
            !has_state(&target).unwrap(),
            "same-version open must honor removal"
        );
        let next = parent.path().join("semantic-pack-catalog.v31");
        drop(open(&next, 31, CatalogOptions::default()).unwrap());
        assert!(
            !has_state(&next).unwrap(),
            "marked empty v30 stops search before populated v29"
        );
        assert_eq!(initialization_version(&next).unwrap(), Some(31));
    }
    #[test]
    fn legacy_nonempty_default_root_is_marked_on_first_open() {
        let parent = tempfile::tempdir().unwrap();
        let source = seed(parent.path());
        let target = parent.path().join("semantic-pack-catalog.v30");
        let stage = tempfile::tempdir_in(parent.path()).unwrap();
        snapshot(&source, stage.path(), &mut Vec::new()).unwrap();
        fs::rename(stage.path(), &target).unwrap();
        assert_eq!(initialization_version(&target).unwrap(), None);
        assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
        assert_eq!(initialization_version(&target).unwrap(), Some(30));
    }
    #[test]
    #[hardwon("#12422: concurrent source removal and GC discarded unrelated installed packs")]
    fn concurrent_gc_retries_each_proven_unlink_and_preserves_other_packs() {
        for removals in [1, 2] {
            let parent = tempfile::tempdir().unwrap();
            let source = parent.path().join("semantic-pack-catalog.v29");
            let writer = Arc::new(
                SemanticPackCatalog::open(
                    &source,
                    CatalogOpenMode::ReadWrite,
                    CatalogOptions::default(),
                )
                .unwrap(),
            );
            writer
                .install(
                    &super::super::go_extraction_support_22::callable_pack(),
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "keep".into(),
                    },
                )
                .unwrap();
            for index in 0..removals {
                let mut authored: crate::analyzer::semantic_model::AuthoredSemanticModelPack =
                    serde_json::from_slice(super::super::go_extraction_support_22::DECLARATIONS)
                        .unwrap();
                authored.schema_version = 10;
                authored.compatibility.bifrost = None;
                authored.pack_id = format!("removed.{index}");
                let pack = crate::analyzer::semantic_model::compile_pack(
                    &authored,
                    &crate::analyzer::semantic_model::CompilerOptions::default(),
                )
                .unwrap();
                writer
                    .install(
                        &pack,
                        &DurablePackSource {
                            kind: DurablePackSourceKind::Installed,
                            source_id: format!("remove-{index}"),
                        },
                    )
                    .unwrap();
            }
            let concurrent = writer.clone();
            let mut next = 0;
            BEFORE_SNAPSHOT_OBJECTS.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    if next < removals {
                        concurrent
                            .remove_source(&DurablePackSource {
                                kind: DurablePackSourceKind::Installed,
                                source_id: format!("remove-{next}"),
                            })
                            .unwrap();
                        let gc = concurrent
                            .garbage_collect(&CatalogGcOptions {
                                minimum_age: Duration::ZERO,
                                ..CatalogGcOptions::default()
                            })
                            .unwrap();
                        assert_eq!(gc.pruned_packs, 1);
                        next += 1;
                    }
                }))
            });
            let target = parent.path().join("semantic-pack-catalog.v30");
            let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
            BEFORE_SNAPSHOT_OBJECTS.with(|slot| slot.borrow_mut().take());
            assert_installed(&catalog);
            let diagnostics = catalog.upgrade_diagnostics().unwrap();
            assert_eq!(diagnostics.len(), removals);
            for diagnostic in &diagnostics {
                assert_eq!(diagnostic.code, "catalog.default_upgrade_retried");
                assert!(diagnostic.message.contains("unlinked since snapshot"));
            }
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|d| &d.message)
                    .collect::<HashSet<_>>()
                    .len(),
                removals,
                "every retry proves a distinct new unlink"
            );
            verify_catalog(&target).unwrap();
            assert_installed(&writer);
        }
    }
    #[test]
    #[hardwon("#12422: a still-linked missing object must not be treated as a concurrent unlink")]
    fn linked_missing_object_recovers_with_failure_instead_of_retry() {
        let parent = tempfile::tempdir().unwrap();
        let source = seed(parent.path());
        let connection = Connection::open(source.join(DB)).unwrap();
        let relative: String = connection
            .query_row(
                "SELECT relative_path FROM catalog_objects LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(connection);
        fs::remove_file(source.join(relative)).unwrap();
        let catalog = open(
            &parent.path().join("semantic-pack-catalog.v30"),
            30,
            CatalogOptions::default(),
        )
        .unwrap();
        assert!(!has_state(&catalog.root).unwrap());
        let diagnostics = catalog.upgrade_diagnostics().unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "catalog.default_upgrade_failed");
        catalog
            .install(
                &super::super::go_extraction_support_22::callable_pack(),
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "normal-acquisition".into(),
                },
            )
            .unwrap();
        assert_installed(&catalog);
    }
    fn sqlite_error(code: i32) -> CatalogError {
        CatalogError::sqlite(
            "previous catalog access",
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None),
        )
    }
    #[test]
    fn source_failure_classifier_preserves_environment_retryability() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::Other,
        ] {
            assert!(
                matches!(
                    predecessor_failure(CatalogError::io(
                        "read previous catalog",
                        std::io::Error::from(kind)
                    )),
                    SnapshotFailure::Environment { .. }
                ),
                "{kind:?}"
            );
        }
        #[cfg(unix)]
        assert!(matches!(
            predecessor_failure(CatalogError::io(
                "read previous catalog",
                std::io::Error::from_raw_os_error(libc::EIO)
            )),
            SnapshotFailure::Environment { .. }
        ));
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_READONLY,
        ] {
            assert!(
                matches!(
                    predecessor_failure(sqlite_error(code)),
                    SnapshotFailure::Environment { .. }
                ),
                "SQLite {code}"
            );
        }
        for code in [
            rusqlite::ffi::SQLITE_CORRUPT,
            rusqlite::ffi::SQLITE_NOTADB,
            rusqlite::ffi::SQLITE_CONSTRAINT,
        ] {
            assert!(
                matches!(
                    predecessor_failure(sqlite_error(code)),
                    SnapshotFailure::Unusable(_)
                ),
                "SQLite {code}"
            );
        }
        assert!(matches!(
            predecessor_failure(CatalogError::io(
                "read previous catalog",
                std::io::Error::from(ErrorKind::NotFound)
            )),
            SnapshotFailure::Unusable(_)
        ));
        assert!(matches!(
            predecessor_failure(CatalogError::CatalogTooNew {
                found: 31,
                supported: 30
            }),
            SnapshotFailure::Unusable(_)
        ));
    }
    #[test]
    #[hardwon("#12422: transient source and stage failures permanently finalized an empty catalog")]
    fn source_and_stage_environment_failures_defer_then_retry_without_marker() {
        for case in ["busy", "locked", "permission", "stage-full", "stage-write"] {
            let parent = tempfile::tempdir().unwrap();
            seed(parent.path());
            let target = parent.path().join("semantic-pack-catalog.v30");
            let phase = if case.starts_with("stage-") {
                "stage-write"
            } else {
                "source"
            };
            let mut fault = Some(match case {
                "busy" => sqlite_error(rusqlite::ffi::SQLITE_BUSY),
                "locked" => sqlite_error(rusqlite::ffi::SQLITE_LOCKED),
                "permission" => CatalogError::io(
                    "read previous catalog",
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                ),
                "stage-full" => sqlite_error(rusqlite::ffi::SQLITE_FULL),
                _ => CatalogError::io(
                    "write staged catalog",
                    std::io::Error::from(std::io::ErrorKind::WriteZero),
                ),
            });
            UPGRADE_FAULT.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |layer| {
                    if layer == phase {
                        Err(fault.take().unwrap())
                    } else {
                        Ok(())
                    }
                }))
            });
            let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
            UPGRADE_FAULT.with(|slot| slot.borrow_mut().take());
            assert!(
                catalog._ephemeral_root.is_some(),
                "{case}: session remains usable"
            );
            let diagnostics = catalog.upgrade_diagnostics().unwrap();
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.code == "catalog.default_upgrade_deferred"),
                "{case}"
            );
            assert!(
                !target.exists(),
                "{case}: no persistent destination or marker"
            );
            assert!(
                fs::read_dir(parent.path()).unwrap().all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".semantic-pack-upgrade-")),
                "failed stage was removed"
            );
            catalog
                .install(
                    &super::super::go_extraction_support_22::callable_pack(),
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "normal-acquisition".into(),
                    },
                )
                .unwrap();
            assert_installed(&catalog);
            drop(catalog);
            // Clearing the fault represents releasing the lock, restoring the
            // permission, or freeing stage space. The predecessor is retried.
            assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
            assert_eq!(initialization_version(&target).unwrap(), Some(30));
        }
    }
    #[test]
    fn real_source_busy_timeout_defers_and_a_later_start_migrates() {
        let parent = tempfile::tempdir().unwrap();
        let source = seed(parent.path());
        let lock = Connection::open(source.join(DB)).unwrap();
        lock.execute_batch("PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE;")
            .unwrap();
        let target = parent.path().join("semantic-pack-catalog.v30");
        let catalog = open(&target, 30, CatalogOptions::default()).unwrap();
        assert!(catalog._ephemeral_root.is_some());
        assert!(
            catalog
                .upgrade_diagnostics()
                .unwrap()
                .iter()
                .any(|d| d.code == "catalog.default_upgrade_deferred")
        );
        assert!(!target.exists());
        lock.execute_batch("ROLLBACK").unwrap();
        drop(lock);
        drop(catalog);
        assert_installed(&open(&target, 30, CatalogOptions::default()).unwrap());
    }
    #[test]
    fn failure_of_the_ephemeral_opener_is_a_typed_open_error() {
        let parent = tempfile::tempdir().unwrap();
        seed(parent.path());
        let target = parent.path().join("semantic-pack-catalog.v30");
        UPGRADE_FAULT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|layer| match layer {
                "source" => Err(sqlite_error(rusqlite::ffi::SQLITE_BUSY)),
                "ephemeral" => Err(CatalogError::io(
                    "create ephemeral catalog root",
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                )),
                _ => Ok(()),
            }))
        });
        let result = open(&target, 30, CatalogOptions::default());
        UPGRADE_FAULT.with(|slot| slot.borrow_mut().take());
        assert!(matches!(
            result,
            Err(CatalogError::Io {
                operation: "create ephemeral catalog root",
                ..
            })
        ));
        assert!(!target.exists());
    }
    #[test]
    fn failed_publication_restores_empty_destination() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("semantic-pack-catalog.v30");
        drop(
            SemanticPackCatalog::open(
                &target,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap(),
        );
        let stage = tempfile::tempdir_in(parent.path()).unwrap();
        fs::remove_dir(stage.path()).unwrap();
        assert!(publish(&target, stage).is_err());
        assert!(target.join(DB).exists());
        assert!(!has_state(&target).unwrap());
    }
}
