use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::CatalogError;

const PATH_INSPECTION_RETRY_DEADLINE: Duration = Duration::from_secs(5);
const PATH_INSPECTION_RETRY_BACKOFF: Duration = Duration::from_millis(5);
const PATH_INSPECTION_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(100);

pub(super) fn prepare_root(root: &Path) -> Result<PathBuf, CatalogError> {
    reject_symlink(root, "catalog root")?;
    let root_existed = root.exists();
    fs::create_dir_all(root).map_err(|error| CatalogError::io("create catalog root", error))?;
    if !root_existed && let Some(parent) = root.parent() {
        sync_directory(parent)?;
    }
    let root = root
        .canonicalize()
        .map_err(|error| CatalogError::io("canonicalize catalog root", error))?;
    for directory in [
        root.join("objects"),
        root.join("objects/sha256"),
        root.join("staging"),
        root.join("locks"),
    ] {
        reject_symlink(&directory, "catalog directory")?;
        let existed = directory.exists();
        fs::create_dir_all(&directory)
            .map_err(|error| CatalogError::io("create catalog directory", error))?;
        if !existed {
            sync_directory(
                directory
                    .parent()
                    .expect("catalog directory always has a parent"),
            )?;
        }
    }
    reject_symlink(
        &root.join(super::db::CATALOG_DB_FILE_NAME),
        "catalog database",
    )?;
    Ok(root)
}

pub(super) fn open_read_only_root(root: &Path) -> Result<PathBuf, CatalogError> {
    reject_symlink(root, "catalog root")?;
    let root = root
        .canonicalize()
        .map_err(|error| CatalogError::io("canonicalize catalog root", error))?;
    for path in [
        root.join("objects"),
        root.join("objects/sha256"),
        root.join(super::db::CATALOG_DB_FILE_NAME),
    ] {
        reject_symlink(&path, "catalog path")?;
    }
    Ok(root)
}

pub(super) fn open_generated_production_lock(
    root: &Path,
    digest: &str,
) -> Result<File, CatalogError> {
    validate_digest(digest)?;
    let lock_root = root.join("locks");
    reject_symlink(&lock_root, "catalog lock directory")?;
    let lock_path = lock_root.join(format!("{digest}.lock"));
    reject_symlink(&lock_path, "generated-production lock")?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|error| CatalogError::io("open generated-production lock", error))
}

pub(super) fn acquire_initialization_lock(root: &Path) -> Result<File, CatalogError> {
    let lock_root = root.join("locks");
    reject_symlink(&lock_root, "catalog lock directory")?;
    let lock_path = lock_root.join("catalog-initialization.lock");
    reject_symlink(&lock_path, "catalog initialization lock")?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|error| CatalogError::io("open catalog initialization lock", error))?;
    file.lock()
        .map_err(|error| CatalogError::io("acquire catalog initialization lock", error))?;
    Ok(file)
}

pub(super) fn publish(
    root: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(PathBuf, bool), CatalogError> {
    validate_digest(digest)?;
    if sha256(bytes) != digest {
        return Err(CatalogError::Integrity(
            "object bytes do not match their stored digest".to_owned(),
        ));
    }
    let relative = relative_object_path(digest);
    let destination = root.join(&relative);
    let parent = destination
        .parent()
        .expect("digest object path always has a parent");
    reject_object_tree(root, parent)?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent)
        .map_err(|error| CatalogError::io("create object prefix directory", error))?;
    reject_symlink(&destination, "catalog object")?;
    let staging = root.join("staging");
    reject_symlink(&staging, "catalog staging directory")?;
    let mut temporary = NamedTempFile::new_in(&staging)
        .map_err(|error| CatalogError::io("create staged object", error))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| CatalogError::io("write staged object", error))?;
    let published = if destination.exists() {
        match verify(&destination, digest, bytes.len() as u64) {
            Ok(()) => return Ok((relative, false)),
            Err(_) => temporary
                .persist(&destination)
                .map_err(|error| CatalogError::io("replace corrupt catalog object", error.error))?,
        }
    } else {
        match temporary.persist_noclobber(&destination) {
            Ok(file) => file,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify(&destination, digest, bytes.len() as u64)?;
                return Ok((relative, false));
            }
            Err(error) => return Err(CatalogError::io("publish staged object", error.error)),
        }
    };
    published
        .sync_all()
        .map_err(|error| CatalogError::io("sync published catalog object", error))?;
    sync_directory(parent)?;
    if !parent_existed {
        sync_directory(&root.join("objects/sha256"))?;
    }
    Ok((relative, true))
}

pub(super) fn read(
    root: &Path,
    relative: &str,
    digest: &str,
    stored_size: u64,
) -> Result<Vec<u8>, CatalogError> {
    validate_digest(digest)?;
    let expected = relative_object_path(digest);
    if Path::new(relative) != expected {
        return Err(CatalogError::Integrity(
            "catalog object path does not match its digest".to_owned(),
        ));
    }
    let path = root.join(expected);
    reject_object_tree(
        root,
        path.parent()
            .expect("digest object path always has a prefix directory"),
    )?;
    reject_symlink(&path, "catalog object")?;
    verify(&path, digest, stored_size)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(stored_size)
            .map_err(|_| CatalogError::Integrity("stored size exceeds usize".to_owned()))?,
    );
    File::open(&path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| CatalogError::io("read catalog object", error))?;
    Ok(bytes)
}

pub(super) fn delete(root: &Path, relative: &str, digest: &str) -> Result<bool, CatalogError> {
    validate_digest(digest)?;
    let expected = relative_object_path(digest);
    if Path::new(relative) != expected {
        return Err(CatalogError::Integrity(
            "catalog object path does not match its digest".to_owned(),
        ));
    }
    let path = root.join(expected);
    reject_object_tree(
        root,
        path.parent()
            .expect("digest object path always has a prefix directory"),
    )?;
    reject_symlink(&path, "catalog object")?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CatalogError::io("delete catalog object", error)),
    }
}

pub(super) fn verify_existing(
    root: &Path,
    relative: &Path,
    digest: &str,
    stored_size: u64,
) -> Result<(), CatalogError> {
    validate_digest(digest)?;
    let expected = relative_object_path(digest);
    if relative != expected {
        return Err(CatalogError::Integrity(
            "catalog object path does not match its digest".to_owned(),
        ));
    }
    let path = root.join(expected);
    reject_object_tree(
        root,
        path.parent()
            .expect("digest object path always has a prefix directory"),
    )?;
    reject_symlink(&path, "catalog object")?;
    verify(&path, digest, stored_size)
}

pub(super) fn visit_object_files(
    root: &Path,
    mut visitor: impl FnMut(PathBuf, String) -> Result<bool, CatalogError>,
) -> Result<(), CatalogError> {
    let sha_root = root.join("objects/sha256");
    reject_symlink(&sha_root, "catalog object directory")?;
    for prefix in fs::read_dir(&sha_root)
        .map_err(|error| CatalogError::io("list catalog object prefixes", error))?
    {
        let prefix =
            prefix.map_err(|error| CatalogError::io("read catalog object prefix", error))?;
        let prefix_path = prefix.path();
        reject_symlink(&prefix_path, "catalog object prefix")?;
        if !prefix
            .file_type()
            .map_err(|error| CatalogError::io("stat catalog object prefix", error))?
            .is_dir()
        {
            continue;
        }
        let prefix_name = prefix.file_name();
        let Some(prefix_name) = prefix_name.to_str() else {
            continue;
        };
        if prefix_name.len() != 2 {
            continue;
        }
        for entry in fs::read_dir(&prefix_path)
            .map_err(|error| CatalogError::io("list catalog objects", error))?
        {
            let entry = entry.map_err(|error| CatalogError::io("read catalog object", error))?;
            let path = entry.path();
            reject_symlink(&path, "catalog object")?;
            if !entry
                .file_type()
                .map_err(|error| CatalogError::io("stat catalog object", error))?
                .is_file()
            {
                continue;
            }
            let Some(suffix) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let digest = format!("{prefix_name}{suffix}");
            if validate_digest(&digest).is_err() {
                continue;
            }
            let relative_path = path
                .strip_prefix(root)
                .expect("catalog object is below root")
                .to_owned();
            if !visitor(relative_path, digest)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

pub(super) fn cleanup_stale_staging(
    root: &Path,
    minimum_age: Duration,
    limit: usize,
) -> Result<(), CatalogError> {
    let staging = root.join("staging");
    reject_symlink(&staging, "catalog staging directory")?;
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in fs::read_dir(&staging)
        .map_err(|error| CatalogError::io("list staged catalog objects", error))?
    {
        if removed == limit {
            break;
        }
        let entry = entry.map_err(|error| CatalogError::io("read staged catalog object", error))?;
        let path = entry.path();
        reject_symlink(&path, "staged catalog object")?;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CatalogError::io("stat staged catalog object", error)),
        };
        if !metadata.is_file() {
            continue;
        }
        let old_enough = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= minimum_age);
        if old_enough {
            match fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(CatalogError::io(
                        "remove stale staged catalog object",
                        error,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn verify(path: &Path, digest: &str, stored_size: u64) -> Result<(), CatalogError> {
    let metadata =
        fs::metadata(path).map_err(|error| CatalogError::io("stat catalog object", error))?;
    if !metadata.is_file() || metadata.len() != stored_size {
        return Err(CatalogError::Integrity(format!(
            "catalog object size mismatch for {digest}"
        )));
    }
    let bytes = fs::read(path).map_err(|error| CatalogError::io("verify catalog object", error))?;
    if sha256(&bytes) != digest {
        return Err(CatalogError::Integrity(format!(
            "catalog object digest mismatch for {digest}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CatalogError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| CatalogError::io("sync catalog object directory", error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), CatalogError> {
    Ok(())
}

fn relative_object_path(digest: &str) -> PathBuf {
    Path::new("objects")
        .join("sha256")
        .join(&digest[..2])
        .join(&digest[2..])
}

fn validate_digest(digest: &str) -> Result<(), CatalogError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CatalogError::Integrity(
            "catalog digest must be lowercase SHA-256 hex".to_owned(),
        ))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn reject_object_tree(root: &Path, prefix: &Path) -> Result<(), CatalogError> {
    for path in [root.join("objects"), root.join("objects/sha256")] {
        reject_symlink(&path, "catalog object directory")?;
    }
    reject_symlink(prefix, "object prefix directory")
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), CatalogError> {
    // Concurrent SQLite/catalog creation can briefly make Windows metadata
    // inspection report ERROR_ACCESS_DENIED. Keep the no-follow check, but give
    // that transient state the same bounded settling window as WAL setup.
    let started = Instant::now();
    let mut backoff = PATH_INSPECTION_RETRY_BACKOFF;
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CatalogError::Integrity(format!(
                    "refusing to use symlinked {label}: {}",
                    path.display()
                )));
            }
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error)
                if cfg!(windows)
                    && error.kind() == std::io::ErrorKind::PermissionDenied
                    && started.elapsed() < PATH_INSPECTION_RETRY_DEADLINE =>
            {
                let remaining = PATH_INSPECTION_RETRY_DEADLINE.saturating_sub(started.elapsed());
                std::thread::sleep(backoff.min(remaining));
                backoff = backoff
                    .saturating_mul(2)
                    .min(PATH_INSPECTION_RETRY_MAX_BACKOFF);
            }
            Err(error) => return Err(CatalogError::io("inspect catalog path", error)),
        }
    }
}
